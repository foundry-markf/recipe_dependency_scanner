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

import argparse
import logging
import os
import pathlib
import re
import subprocess
import sys

# see https://docs.conan.io/en/latest/reference/conanfile/attributes.html#name
CONAN_PACKAGENAME = "[a-zA-Z0-9_][a-zA-Z0-9_\+\.-]{1,50}"
# regex to find the name attribute in a recipe
PACKAGENAME_ATTR = fr"\s+name\b\s*=\s*['\"]({CONAN_PACKAGENAME})['\"]\s+$"

# regex that scans for "name/version[@" that maps to the name and version of a Conan package reference
# this will pick up the requires/build_requires attribute (scalar, list, tuple versions) as well as self.requires and self.build_requires
# function arguments
# the {} in the version match is for using {}.format to parameterise the version (should also pick up on f-strings)
PACKAGEREFERENCE  = fr"['\"]([^/@]{CONAN_PACKAGENAME})/(?:[A-Za-z0-9\._{{}}^@^\"]+)[@|'\"]"

# combined regex
PACKAGEREFERENCEREGEX = re.compile("|".join([PACKAGENAME_ATTR, PACKAGEREFERENCE]))


def _get_package_name(recipe_path):
    """
    Get the package name using 'conan inspect'.
    This is slow.
    Returns a string.
    """
    output = subprocess.check_output(["conan", "inspect", "--raw", "name", recipe_path])
    return output.decode("utf8").strip()


def _extract_recipe_details(recipe_path):
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
            if (match[0]):
                logging.debug("Found name on line %s: '%s'" % (i+1, match[0]))
                name = match[0]
                continue
            if (match[1]):
                logging.debug("Found dependent on line %s: '%s'" % (i+1, match[1]))
                dependents.append(match[1])
    assert name, f"No name was found in {recipe_path}"
    return name, dependents


def _get_package_names_from_buckets(buckets):
    """
    Get a list of names of all packages in all buckets.
    """
    return set([p["name"] for b in buckets for p in b])


def scan(list_of_recipe_paths, find_all, verify, downstream_from):
    """
    Scan the list of recipe paths, and convert to buckets of packages, satisfying dependencies, that can be built in parallel.

    Optionally scan the current directory for all conanfile.py files.
    Optionally verify the package names extracted by regex from the recipe files using slower conan CLI commands.
    Optionally find all downstream packages from a named starting recipe.
    """
    if downstream_from:
        find_all=True
    if find_all:
        list_of_recipe_paths = [path for path in pathlib.Path.cwd().glob("**/conanfile.py") if not path.parent.name.startswith("test_")]
    if not list_of_recipe_paths:
        logging.critical("No recipe paths were provided")
        sys.exit(1)

    packages = []
    recipe_path_count = len(list_of_recipe_paths)
    logging.debug(f"{recipe_path_count} recipes to scan")
    for i, path in enumerate(list_of_recipe_paths):
        logging.debug(f"Scanning recipe {i}/{recipe_path_count}: {pathlib.Path.cwd() / path}")
        name, dependents = _extract_recipe_details(path)
        logging.debug(f"Package name: '{name}'")
        if verify:
            pkg_name_from_conan = _get_package_name(path)
            assert name == pkg_name_from_conan, f"Inconsistent names found in {path}: Conan inspect: '{pkg_name_from_conan}'; regex: '{name}'"
        package = {
            "name": name,
            "path": path
        }
        if dependents:
            package["dependents"] = dependents
        packages.append(package)

    # might be some bad regexs, or packages not yet in the recipes folder
    # remove bad dependents
    all_package_names = [p["name"] for p in packages]
    for p in packages:
        if not "dependents" in p:
            continue
        bad_dependent_names = []
        for d in p["dependents"]:
            if not d in all_package_names:
                logging.debug(f"Recipe: {p['name']} dependent {d} not found in all package list")
                bad_dependent_names.append(d)
        for n in bad_dependent_names:
            p["dependents"].remove(n)

    logging.debug("All packages found:")
    for p in packages:
        if "dependents" in p:
            logging.debug(f"{p['name']}: {p['path']}: {p['dependents']}")
        else:
            logging.debug(f"{p['name']}: {p['path']}")

    # convert to buckets (assumes non cyclic dependencies)
    # this is between O(n) and O(n^2) complexity, as need to loop over a list reducing in size (at a variable rate) each iteration
    # Algorithm:
    # - find all dependencies with zero dependencies - this is the first bucket - remove these from the outstanding list
    # - while outstanding packages remain
    #   - get a list of package names from all existing buckets
    #   - for each outstanding package:
    #     - are all of its dependencies in a bucket?
    #       - YES: add package to the next bucket
    #       - NO; leave it to be processed in another bucket
    #   - if nothing has been added to the next bucket - ERROR

    if downstream_from:
        downstream_package = [package for package in packages if package["name"] == downstream_from]
        assert len(downstream_package) == 1, f"Unable to find the starting package called '{downstream_from}' in all recipe paths. Check the case."

    buckets = []
    # those without any dependencies can be built initially
    bucket0 = [package for package in packages if "dependents" not in package]
    if bucket0:
        buckets.append(bucket0)
        for p in bucket0:
            packages.remove(p)
    # now scan for all those remaining that can completely satisfy their dependencies in the existing buckets
    # once all packages that can be satisfied with existing buckets are found, these form the next bucket
    # continue until all packages are exhausted
    while packages:
        next_bucket = []
        bucketed_names = _get_package_names_from_buckets(buckets)
        logging.debug(f"Bucketed names so far: {bucketed_names}")
        for p in packages:
            logging.debug(f"Considering package dependencies for recipe: {p['name']}")
            found_all = True
            for d in p["dependents"]:
                logging.debug(f"\tLooking for {d}")
                if d not in bucketed_names:
                    found_all = False
                    break
            if found_all:
                next_bucket.append(p)
        if next_bucket:
            for p in next_bucket:
                packages.remove(p)
            buckets.append(next_bucket)
        else:
            raise RuntimeError("Unable to resolve any packages that can be built next")

    if downstream_from:
        # this performs post-processing to cull the buckets of unnecessary packages
        # find the bucket that the downstream starting package lives in, removing earlier buckets
        while buckets:
            found = [p for p in buckets[0] if p["name"] == downstream_from]
            buckets.pop(0)
            if found:
                buckets.insert(0, found)
                break

        # cull any downstream recipes that don't have any of the bucketed packages as dependents
        up_to_bucket = 1
        for b in buckets[1:]:
            bucketed_names = _get_package_names_from_buckets(buckets[:up_to_bucket])
            to_cull = []
            for p in b:
                found_any = False
                for d in p["dependents"]:
                    logging.debug(f"\tLooking for {d}")
                    if d in bucketed_names:
                        found_any = True
                        break
                if not found_any:
                    to_cull.append(p)
            for c in to_cull:
                logging.debug(f"Culling unrelated '{c['name']}' from bucket {up_to_bucket}")
                b.remove(c)
            up_to_bucket += 1
        # there may now be empty buckets
        buckets = [b for b in buckets if b]

    return buckets


def _print_buckets(buckets):
    for i, b in enumerate(buckets):
        names = sorted(list(set([p["name"] for p in b])), key=str.casefold)
        logging.critical(f"Bucket {i}: {names}")


if __name__ == "__main__":
    logging.getLogger().setLevel(os.environ.get("LOGLEVEL", "INFO"))
    parser = argparse.ArgumentParser(description="Scan recipes for dependencies to determine a build order of packages grouped into buckets that can be built in parallel")
    parser.add_argument("--all", action="store_true", help="Glob for conanfile.py recursively from the current directory to find all recipes")
    parser.add_argument("--verify", action="store_true", help="Verify the recipe name found by invoking 'conan inspect'. This is slow.")
    parser.add_argument("--downstream-from", help="Specify the package name to start from, and add all downstream consumers of it, recursively. Implies --all in order to locate the package name in a recipe.")
    parser.add_argument("recipe_paths", nargs="*", help="One or more paths to conanfile.py for each recipe to organise into build order.")
    args = parser.parse_args()
    buckets = scan(args.recipe_paths, find_all=args.all, verify=args.verify, downstream_from=args.downstream_from)

    logging.critical(f"There were {len(buckets)} buckets of packages determined")
    if args.downstream_from:
        logging.critical(f"Listing from package {args.downstream_from} to all consuming downstream recipes (recursively), this is the package build order:")
    else:
        logging.critical("Listing from fewest dependencies to most dependencies, this is the package build order:")
    _print_buckets(buckets)
