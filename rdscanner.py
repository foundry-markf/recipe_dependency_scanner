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
    dependents: typing.List[str]


# see https://docs.conan.io/en/latest/reference/conanfile/attributes.html#name
CONAN_PACKAGENAME = r"[a-zA-Z0-9_][a-zA-Z0-9_\+\.-]{1,50}"
# regex to find the name attribute in a recipe
PACKAGENAME_ATTR = rf"\s+name\b\s*=\s*['\"]({CONAN_PACKAGENAME})['\"]\s+$"

# regex that scans for "name/version[@" that maps to the name and version of a Conan package reference
# this will pick up the requires/build_requires attribute (scalar, list, tuple versions) as well as self.requires and self.build_requires
# function arguments
# the {} in the version match is for using {}.format to parameterise the version (should also pick up on f-strings)
PACKAGEREFERENCE = (
    rf"['\"]([^/@]{CONAN_PACKAGENAME})/(?:[A-Za-z0-9\._{{}}^@^\"]+)[@|'\"]"
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


def _extract_recipe_details(recipe_path: str) -> typing.Tuple[str, typing.List[str]]:
    """
    Extract package name and a list of dependent package names (runtime and buildtime) from the specified recipe.
    Returns a tuple containing a string and a list of strings.
    """
    name = None
    dependents = []
    for i, line in enumerate(open(recipe_path, "rt")):
        for match in re.findall(PACKAGEREFERENCEREGEX, line):
            if not match:
                continue
            if match[0]:
                logging.debug("Found name on line %s: '%s'" % (i + 1, match[0]))
                name = match[0]
                continue
            if match[1]:
                logging.debug("Found dependent on line %s: '%s'" % (i + 1, match[1]))
                dependents.append(match[1])
    assert name, f"No name was found in {recipe_path}"
    return name, dependents


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
) -> typing.List[typing.List[str]]:
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
    logging.debug(f"{recipe_path_count} recipes to scan")
    for i, path in enumerate(list_of_recipe_paths):
        logging.debug(
            f"Scanning recipe {i}/{recipe_path_count}: {pathlib.Path.cwd() / path}"
        )
        name, dependents = _extract_recipe_details(path)
        logging.debug(f"Package name: '{name}'")
        if verify:
            pkg_name_from_conan = _get_package_name(path)
            assert (
                name == pkg_name_from_conan
            ), f"Inconsistent names found in {path}: Conan inspect: '{pkg_name_from_conan}'; regex: '{name}'"
        if name not in packages:
            packages[name] = []
        packages[name].append(PackageMeta(path, dependents))

    # might be some bad regexs, or packages not yet in the recipes folder
    # remove bad dependents
    all_package_names = packages.keys()
    for name, meta_list in packages.items():
        for meta in meta_list:
            if not meta.dependents:
                continue
            bad_dependent_names = []
            for d in meta.dependents:
                if d == name:
                    logging.debug(
                        f"Recipe for '{name}' refers to itself in a dependency"
                    )
                    bad_dependent_names.append(d)
                    continue
                if d not in all_package_names:
                    logging.debug(
                        f"Recipe for '{name}' is dependent upon package '{d}' which is not found in the discovered package list"
                    )
                    bad_dependent_names.append(d)
                    continue
            for n in bad_dependent_names:
                meta.dependents.remove(n)

    logging.debug("All packages found:")
    for name, meta_list in packages.items():
        logging.debug("%s:", name)
        for meta in meta_list:
            logging.debug("\t%s", meta)

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
        logging.debug(f"Bucketed names so far: {bucketed_names}")
        for name, meta_list in packages.items():
            logging.debug(f"Considering package dependencies for recipe: {name}")
            found_all_deps = True
            for meta in meta_list:
                for d in meta.dependents:
                    logging.debug(f"\tLooking for {d}")
                    if d not in bucketed_names:
                        found_all_deps = False
                        break
            if found_all_deps:
                next_bucket.append(name)
        if next_bucket:
            for p in next_bucket:
                del packages[p]
            buckets.append(next_bucket)
        else:
            raise RuntimeError("Unable to resolve any packages that can be built next")

    if downstream_from:
        # this performs post-processing to cull the buckets of unnecessary packages
        # find the bucket that the downstream starting package lives in, removing earlier buckets
        while buckets:
            if downstream_from in buckets[0]:
                break
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
                        logging.debug(f"\tLooking for {d}")
                        if d in bucketed_names:
                            found_any = True
                            break
                if not found_any:
                    to_cull.append(p)
            for c in to_cull:
                logging.debug(f"Culling unrelated '{c}' from bucket {up_to_bucket}")
                b.remove(c)
            up_to_bucket += 1
        # there may now be empty buckets
        buckets = [b for b in buckets if b]

    return buckets


def _print_buckets(buckets: typing.List[typing.List[str]]) -> None:
    for i, b in enumerate(buckets):
        names = sorted(list(set([p for p in b])), key=str.casefold)
        logging.critical(f"Bucket {i}: {names}")


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
        "--verify",
        action="store_true",
        help="Verify the recipe name found by invoking 'conan inspect'. This is slow.",
    )
    parser.add_argument(
        "--downstream-from",
        help="Specify the package name to start from, and add all downstream consumers of it, recursively. Implies --all in order to locate the package name in a recipe.",
    )
    parser.add_argument(
        "recipe_paths",
        nargs="*",
        help="One or more paths to conanfile.py for each recipe to organise into build order.",
    )
    args = parser.parse_args()
    buckets = scan(
        args.recipe_paths,
        find_all=args.all,
        verify=args.verify,
        downstream_from=args.downstream_from,
    )

    logging.critical(f"There were {len(buckets)} buckets of packages determined")
    if args.downstream_from:
        logging.critical(
            f"Listing from package {args.downstream_from} to all consuming downstream recipes (recursively), this is the package build order:"
        )
    else:
        logging.critical(
            "Listing from fewest dependencies to most dependencies, this is the package build order:"
        )
    _print_buckets(buckets)
