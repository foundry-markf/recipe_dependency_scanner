#!/usr/bin/env python

"""
Dependency scanner for Conan recipes.
Output: A list of lists of recipe build orders, satisfying dependencies

Input:
 - Either: a number of paths to conanfile.py's, and the dependencies just between them are determined
 - Or: --all, assumes to be running in the root directory containing recipes, loads all recipes, figures out their build order from the ground up

# TODO: alternative mode to -all, specify a starting (--start-recipe-path) point, instead of those with zero dependencies
"""

import argparse
import logging
import os
import pathlib
import re
import subprocess
import sys


# regex that scans for "name/version[@" that maps to the name and version of a Conan package reference
# this will pick up the requires/build_requires attribute (scalar, list, tuple versions) as well as self.requires and self.build_requires
# function arguments
# the {} in the version match is for using {}.format to parameterise the version (should also pick up on f-strings)
PACKAGENAME = r"\bname\s*=\s*['\"]([a-zA-z0-9]+)['\"]"
PACKAGEREFERENCE  = r"['\"]([^/@][A-Za-z0-9_\.]+)/(?:[A-Za-z0-9\._{}^@^\"]+)[@|'\"]"
PACKAGEREFERENCEREGEX = re.compile("|".join([PACKAGENAME, PACKAGEREFERENCE]))


def _get_package_name(recipe_path):
    output = subprocess.check_output(["conan", "inspect", "--raw", "name", recipe_path])
    return output.decode("utf8").strip()


def _get_recipe_dependents(recipe_path):
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


def scan(list_of_recipe_paths, find_all, verify):
    if find_all:
        list_of_recipe_paths = [path for path in pathlib.Path.cwd().glob("**/conanfile.py") if path.parent.name != "test_package"]
    if not list_of_recipe_paths:
        logging.critical("No recipe paths were provided")
        sys.exit(1)

    packages = []
    logging.debug(f"{len(list_of_recipe_paths)} recipes to scan")
    for path in list_of_recipe_paths:
        logging.debug(f"Scanning recipe: {pathlib.Path.cwd() / path}")
        name, dependents = _get_recipe_dependents(path)
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

    def print_bucket(bucket, index):
        names = [b["name"] for b in bucket]
        logging.critical(f"Bucket {index}:")
        logging.critical(names)

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
    buckets = []
    # those without any dependencies
    bucket0 = [package for package in packages if "dependents" not in package]
    if bucket0:
        buckets.append(bucket0)
        for p in bucket0:
            packages.remove(p)
    # now scan for all those remaining that can completely satisfy their dependencies in the buckets
    while packages:
        next_bucket = []
        bucketed_names = []
        for b in buckets:
            bucketed_names.extend([p["name"] for p in b])
        logging.debug(f"Bucketed names so far: {bucketed_names}")
        for p in packages:
            logging.debug(f"Considering package dependencies for recipe: {p['name']}")
            found_all = True
            for d in p["dependents"]:
                logging.debug(f"Looking for {d}")
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

    logging.debug(f"There were {len(buckets)} buckets of packages determined")
    logging.debug("Listing from fewest dependencies to most dependencies, this is the package build order:")
    for i, b in enumerate(buckets):
        print_bucket(b, i)


if __name__ == "__main__":
    logging.getLogger().setLevel(os.environ.get("LOGLEVEL", "INFO"))
    parser = argparse.ArgumentParser(description="Scan recipes for dependencies to determine a build order of packages grouped into buckets that can be built in parallel")
    parser.add_argument("--all", action="store_true", help="Glob for conanfile.py recursively from the current directory to find all recipes")
    parser.add_argument("--verify", action="store_true", help="Verify the recipe name found by invoking 'conan inspect'. This is slow.")
    parser.add_argument("recipe_paths", nargs="*", help="One or more paths to conanfile.py for each recipe to organise into build order.")
    args = parser.parse_args()
    scan(args.recipe_paths, find_all=args.all, verify=args.verify)
