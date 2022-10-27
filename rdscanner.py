#!/usr/bin/env python

"""
Dependency scanner for Conan recipes.
Output: A list of lists of recipe build orders, satisfying dependencies

Input:
 - Either: a number of paths to conanfile.py's, and the dependencies just between them are determined
   - Use case: continuous integration
 - Or: --all, assumes to be running in the root directory containing recipes, loads all recipes, figures out their build order from the ground up
   - Use case: New VFX refspec build
 - Or: --downstream-from=<package name>, figures out the downstream build order from that specified
   - Use case: Problem found in package A, and implies needing to update all downstream consumers of A (recursively)

TODO: does the --downstream-from option need to be expanded to have multiple starting points? possibly an unlikely use case
"""

from dataclasses import dataclass
import argparse
import copy
import logging
import os
import pathlib
import re
import subprocess
import sys
import typing


@dataclass
class PackageMeta:
    recipe_path: str
    pkgname: str
    dependents: typing.List[str]
    is_header_only: bool
    has_build_method: bool
    recipe_loc: int


# see https://docs.conan.io/en/latest/reference/conanfile/attributes.html#name
# changed {1,50} to {0,50} to allow for single version strings with ranges
CONAN_PACKAGENAME = r"[a-zA-Z0-9_][a-zA-Z0-9_\+\.-]{0,50}"
# regex to find the name attribute in a recipe
PACKAGENAME_ATTR = rf"\s+name\b\s*=\s*['\"]({CONAN_PACKAGENAME})['\"]\s+$"

# regex that scans for "name/version[@..." that maps to the name and version of a Conan package reference
# this will pick up the requires/build_requires attribute (scalar, list, tuple versions) as well as self.requires and self.build_requires
# function arguments
# the |{} in the version match is for using {}.format to parameterise the version (should also pick up on f-strings)
# the (?:\[~)? and (?:\])?
PACKAGEREFERENCE = (
    rf"[\s+\[\(][\"\']({CONAN_PACKAGENAME})/(?:\[~)?({CONAN_PACKAGENAME}|{{}})(?:\])?[\"\'@]"
)

# combined regex
PACKAGEREFERENCEREGEX = re.compile("|".join([PACKAGENAME_ATTR, PACKAGEREFERENCE]))


def _get_package_name(recipe_path: str) -> str:
    """
    Get the package name using 'conan inspect'.
    This is slow.
    Returns a string.
    """
    output = subprocess.check_output(["conan", "inspect", "--raw", "name", recipe_path])
    return output.decode("utf8").strip()


def _extract_recipe_details(recipe_path: str) -> typing.Tuple[str, typing.List[str], bool, bool]:
    """
    Extract package name and a list of dependent package names (runtime and buildtime) from the specified recipe.
    Also extracted is whether the recipe is marked header only, and whether there is a build method that does work.
    Returns a tuple containing a string, a list of strings, and two bools.
    """
    name = None
    dependents = []
    is_header_only = False
    has_build_method = False
    has_settings = False
    has_options = False
    loc = 0
    with open(recipe_path, "rt", encoding="utf-8") as file:
        build_method_indentation = None
        for i, line in enumerate(file):
            loc = loc + 1
            for match in re.findall(PACKAGEREFERENCEREGEX, line):
                if not match:
                    continue
                if match[0]:
                    logging.debug("Found name on line %d: '%s'", i + 1, match[0])
                    name = match[0]
                    continue
                if match[1]:
                    logging.debug("Found dependent on line %d: '%s'", i + 1, match[1])
                    dependents.append(match[1])
            if "settings =" in line.lstrip():
                has_settings = True
                continue
            if "options =" in line.lstrip():
                has_options = True
                continue
            if "self.info.header_only()" in line:
                is_header_only = True
                continue
            if "def build(self)" in line:
                build_method_indentation = len(line) - len(line.lstrip())
                continue
            if build_method_indentation:
                stripped_line = line.lstrip()
                if stripped_line.startswith("#"):
                    continue
                if stripped_line.startswith("pass"):
                    continue
                if stripped_line.startswith("print(") or stripped_line.startswith("self.output"):
                    # some build methods are just printing message!!!
                    continue
                current_indentation = len(line) - len(stripped_line)
                if current_indentation <= build_method_indentation:
                    # we're out of the build method, not having encountered any useful statements
                    build_method_indentation = None
                    continue
                # has build instructions
                has_build_method = True
                build_method_indentation = None

    assert name, f"No name was found in {recipe_path}"
    # some header only libs have not used self.info.header_only()
    return name, dependents, is_header_only or (not has_settings and not has_options), has_build_method, loc


def _get_package_names_from_buckets(
    buckets: typing.List[typing.List[str]],
) -> typing.List[str]:
    """
    Get a list of names of all packages in all buckets.
    """
    names = []
    for b in buckets:
        for n in b:
            assert n not in names
        names.extend(b)
    return names


def scan(
    list_of_recipe_paths: typing.List[str],
    find_all: bool,
    verify: bool,
    downstream_from: typing.Optional[str],
) -> typing.Tuple[typing.List[typing.List[str]], typing.Dict[str, typing.List[PackageMeta]]]:
    """
    Scan the list of recipe paths, and convert to buckets of packages, satisfying dependencies, that can be built in parallel.

    Optionally scan the current directory for all conanfile.py files.
    Optionally verify the package names extracted by regex from the recipe files using slower conan CLI commands.
    Optionally find all downstream packages from a named starting recipe.

    Returns list of list of package names. Each list's dependencies is fully satisfied by the previous lists.
    """
    if downstream_from:
        find_all = True
    if find_all:
        list_of_recipe_paths = [
            str(path)
            for path in pathlib.Path.cwd().glob("**/conanfile.py")
            if not path.parent.name.startswith("test_")
        ]
    if not list_of_recipe_paths:
        logging.critical("No recipe paths were provided")
        sys.exit(1)

    packages: typing.Dict[str, typing.List[PackageMeta]] = {}
    recipe_path_count = len(list_of_recipe_paths)
    logging.debug("%d recipes to scan", recipe_path_count)
    for i, path in enumerate(list_of_recipe_paths):
        logging.debug(
            "Scanning recipe %d/%d: %s", i, recipe_path_count, pathlib.Path.cwd() / path
        )
        name, dependents, is_header_only, has_build_method, recipe_loc = _extract_recipe_details(path)
        logging.debug("Package name: '%s'", name)
        if verify:
            pkg_name_from_conan = _get_package_name(path)
            assert (
                name == pkg_name_from_conan
            ), f"Inconsistent names found in {path}: Conan inspect: '{pkg_name_from_conan}'; regex: '{name}'"
        if name not in packages:
            packages[name] = []
        packages[name].append(PackageMeta(path, name, dependents, is_header_only, has_build_method, recipe_loc))

    # might be some bad regexs, or packages not yet in the recipes folder
    # remove bad dependents
    all_package_names = packages.keys()
    all_bad_dependent_names = []
    for name, meta_list in packages.items():
        for meta in meta_list:
            if not meta.dependents:
                continue
            bad_dependent_names = []
            for d in meta.dependents:
                if d == name:
                    logging.debug(
                        "Recipe for '%s' refers to itself in a dependency", name
                    )
                    bad_dependent_names.append(d)
                    continue
                if d not in all_package_names:
                    logging.debug(
                        "Recipe for '%s' is dependent upon package '%s' which is not found in the discovered package list",
                        name,
                        d,
                    )
                    bad_dependent_names.append(d)
                    continue
            for n in bad_dependent_names:
                meta.dependents.remove(n)
            all_bad_dependent_names.extend(bad_dependent_names)

    logging.debug("All packages found:")
    for name, meta_list in packages.items():
        logging.debug("%s:", name)
        for meta in meta_list:
            logging.debug("\t%s", meta)

    if all_bad_dependent_names:
        logging.debug("Dependents that have no knowledge")
        for bad in all_bad_dependent_names:
            logging.debug("\t%s", bad)

    # sort the packages in the order of increasing dependent counts
    p_order = {}
    for name, meta_list in packages.items():
        # this count is a bit weird, as it's a summation from all recipes under the name
        dep_count = 0
        for meta in meta_list:
            dep_count += len(meta.dependents)
        p_order[name] = dep_count
    ordered_tuple = sorted(p_order.items(), key=lambda x: x[1])

    ordered_packages = {}
    for n, _ in ordered_tuple:
        ordered_packages[n] = packages[n]
    packages = ordered_packages

    # record all packages, as the original is mutable
    all_packages = copy.deepcopy(packages)

    # convert to buckets (assumes non cyclic dependencies)
    # this is between O(n) and O(n^2) complexity, as need to loop over a list reducing in size (at a variable rate) each iteration
    # Algorithm:
    # - find all dependencies with zero dependencies - this is the first bucket - remove these from the outstanding list
    # - while outstanding packages remain
    #   - get a list of package names from all existing buckets
    #   - for each outstanding package:
    #     - are all of its dependencies in a bucket?
    #       - YES: add package to the next bucket
    #       - NO; leave it to be processed in another bucket
    #   - if nothing has been added to the next bucket - ERROR

    if downstream_from:
        assert downstream_from in packages

    buckets = []
    # those without any dependencies can be built initially
    bucket0 = []
    for name, meta_list in packages.items():
        suitable = True
        for meta in meta_list:
            if meta.dependents:
                suitable = False
                break
        if suitable:
            bucket0.append(name)
    if bucket0:
        # TODO: this would be weird if this wasn't always here for any given complex recipe collection
        buckets.append(bucket0)
        for p in bucket0:
            del packages[p]
    # now scan for all those remaining that can completely satisfy their dependencies in the existing buckets
    # once all packages that can be satisfied with existing buckets are found, these form the next bucket
    # continue until all packages are exhausted
    while packages:
        next_bucket = []
        bucketed_names = _get_package_names_from_buckets(buckets)
        logging.debug("Bucketed names so far: %s", bucketed_names)
        logging.debug("Packages remaining: %s", [name for name, _ in packages.items()])
        not_found = []
        for name, meta_list in packages.items():
            logging.debug("Considering package dependencies for recipe: %s", name)
            found_all_deps = True
            # if we've no contenders yet, but a failed search is what we're looking for now
            # figure out if we can pull this out one (it mustn't depend on anything in the outstanding list)
            if not next_bucket and name in not_found:
                logging.debug("\t%s is a potential qualifier to pull out", name)
                good = True
                for meta in meta_list:
                    for d in meta.dependents:
                        # one circular argument, Qt and jom
                        if d in packages and not (d == "jom" and name == "Qt"):
                            logging.debug("\t\tbut dependency %s is also in the current list so no", d)
                            good = False
                            break
                if good:
                    next_bucket.append(name)
                    continue
            for meta in meta_list:
                for d in meta.dependents:
                    logging.debug("\tLooking for %s", d)
                    if d not in bucketed_names:
                        found_all_deps = False
                        not_found.append(d)
                        break
            if found_all_deps:
                next_bucket.append(name)
        if next_bucket:
            for p in next_bucket:
                del packages[p]
            buckets.append(next_bucket)
        else:
            raise RuntimeError(f"Unable to break down the package list into ordered buckets any more: left over {packages}")

    if downstream_from:
        # this performs post-processing to cull the buckets of unnecessary packages
        # find the bucket that the downstream starting package lives in, removing earlier buckets
        while buckets:
            if downstream_from in buckets[0]:
                break
            for name in buckets[0]:
                del all_packages[name]
            buckets.pop(0)

        # cull any downstream recipes that don't have any of the bucketed packages as dependents
        up_to_bucket = 1
        for b in buckets[1:]:
            bucketed_names = _get_package_names_from_buckets(buckets[:up_to_bucket])
            to_cull = []
            for p in b:
                found_any = False
                for meta in all_packages[p]:
                    for d in meta.dependents:
                        logging.debug("\tLooking for %s", d)
                        if d in bucketed_names:
                            found_any = True
                            break
                if not found_any:
                    to_cull.append(p)
            for c in to_cull:
                logging.debug("Culling unrelated '%s' from bucket %d", c, up_to_bucket)
                b.remove(c)
                del all_packages[c]
            up_to_bucket += 1
        # there may now be empty buckets
        buckets = [b for b in buckets if b]

        # ensure that any dependents referencing deleted packages are also deleted
        for _, pkg_meta in all_packages.items():
            for meta in pkg_meta:
                to_delete = []
                for dep in meta.dependents:
                    if dep not in all_packages:
                        to_delete.append(dep)
                for td in to_delete:
                    meta.dependents.remove(td)

    return buckets, all_packages


def _package_label(meta: PackageMeta) -> str:
    if meta.is_header_only:
        return f"{meta.pkgname} (H {meta.recipe_loc})"
    if not meta.has_build_method:
        return f"{meta.pkgname} (BIN {meta.recipe_loc})"
    return f"{meta.pkgname} ({meta.recipe_loc})"


def _print_buckets(buckets: typing.List[typing.List[str]], packages: typing.Dict[str, typing.List[PackageMeta]], flat: bool) -> None:
    for i, b in enumerate(buckets):
        names = sorted(list(set([p for p in b])), key=str.casefold)
        if flat:
            print(f"= Bucket {i} =")
            for name in names:
                print(_package_label(packages[name][0]))
        else:
            annotated_names = [_package_label(packages[name][0]) for name in names]
            logging.critical("Bucket %d: %s", i, annotated_names)


def _save_mxgraph(buckets: typing.List[typing.List[str]], packages: typing.Dict[str, typing.List[PackageMeta]], output_path: str) -> None:
    import pygraphviz as pgv
    from graphviz2drawio import graphviz2drawio

    def _package_mxgraph_node(meta: PackageMeta, graph: pgv.AGraph) -> None:
        colours = {
            0: "#FFFFFF",
            1: "#EEEEEE",
            2: "#DDDDDD",
            3: "#CCCCCC",
            4: "#BBBBBB",
            5: "#AAAAAA",
            6: "#999999",
            7: "#888888",
            8: "#777777",
            9: "#666666",
        }
        header_only_colour = "#FFFF00"
        prepackaged_binary_package_color = "#00FFFF"

        label = f"{meta.pkgname}\n{meta.recipe_loc} LOC"

        if meta.is_header_only:
            g.add_node(meta.pkgname, label=label, fill=header_only_colour, shape="box")
        elif not meta.has_build_method:
            g.add_node(meta.pkgname, label=label, fill=prepackaged_binary_package_color, shape="box")
        else:
            g.add_node(meta.pkgname, label=label, fill=colours[i], shape="box")

    G = pgv.AGraph(rankdir="LR", directed=True, strict=True)
    for i, b in enumerate(buckets):
        g = G.add_subgraph(f"Bucket {i}")
        for name in reversed(sorted(list(set([p for p in b])), key=str.casefold)):
            _package_mxgraph_node(packages[name][0], g)
    for name, deps in packages.items():
        for dep in deps:
            for d in dep.dependents:
                G.add_edge(d, name)
    G = G.acyclic()
    xml = graphviz2drawio.convert(G)
    with open(output_path, "wt") as out:
        out.write(xml)
    logging.info("Written out mxgraph to %s", output_path)


if __name__ == "__main__":
    logging.getLogger().setLevel(os.environ.get("LOGLEVEL", "INFO"))
    parser = argparse.ArgumentParser(
        description="Scan recipes for dependencies to determine a build order of packages grouped into buckets that can be built in parallel"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Glob for conanfile.py recursively from the current directory to find all recipes",
    )
    parser.add_argument(
        "--flat",
        action="store_true",
        help="Display output as a flattened list",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify the recipe name found by invoking 'conan inspect'. This is slow.",
    )
    parser.add_argument(
        "--downstream-from",
        help="Specify the package name to start from, and add all downstream consumers of it, recursively. Implies --all in order to locate the package name in a recipe.",
    )
    parser.add_argument(
        "--mxgraph-out",
        help="Specify the output path for an mxgraph",
    )
    parser.add_argument(
        "recipe_paths",
        nargs="*",
        help="One or more paths to conanfile.py for each recipe to organise into build order.",
    )
    args = parser.parse_args()
    buckets, packages = scan(
        args.recipe_paths,
        find_all=args.all,
        verify=args.verify,
        downstream_from=args.downstream_from,
    )

    logging.critical("There were %d buckets of packages determined", len(buckets))
    if args.downstream_from:
        logging.critical(
            "Listing from package %s to all consuming downstream recipes (recursively), this is the package build order:",
            args.downstream_from,
        )
    else:
        logging.critical(
            "Listing from fewest dependencies to most dependencies, this is the package build order:"
        )
    _print_buckets(buckets, packages, args.flat)
    if args.mxgraph_out:
        _save_mxgraph(buckets, packages, args.mxgraph_out)
