#!/usr/bin/env python

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
PACKAGEREFERENCE  = "['\"]([^/@][A-Za-z0-9_\.]+)/(?:[A-Za-z0-9\._{}^@^\"]+)[@|'\"]"
PACKAGEREFERENCEREGEX = re.compile(PACKAGEREFERENCE)


def _get_package_name(recipe_path):
    output = subprocess.check_output(["conan", "inspect", "--raw", "name", recipe_path])
    return output.decode("utf8").strip()


def _get_recipe_dependents(recipe_path):
    dependents = []
    for i, line in enumerate(open(recipe_path, "rt")):
        for match in re.findall(PACKAGEREFERENCEREGEX, line):
            logging.debug("Found dependent on line %s: %s" % (i+1, match))
            dependents.append(match)
    return dependents


def scan(list_of_recipe_paths, find_all=False):
    #if not list_of_recipe_paths:
    if find_all:
        list_of_recipe_paths = [path for path in pathlib.Path.cwd().glob("**/conanfile.py") if path.parent.name != "test_package"]
        #list_of_recipe_paths = list_of_recipe_paths[:5] # TEMPORARY
    if not list_of_recipe_paths:
        logging.critical("No recipe paths were provided")
        sys.exit(1)

    packages = []
    logging.debug(f"{len(list_of_recipe_paths)} recipes to scan")
    for path in list_of_recipe_paths:
        logging.debug(f"Scanning recipe: {pathlib.Path.cwd() / path}")
        pkg_name = _get_package_name(path)
        logging.debug(f"Package name: {pkg_name}")
        package = {
            "name": pkg_name,
            "path": path
        }
        dependents = _get_recipe_dependents(path)
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

    # convert to buckets
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
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("recipe_paths", nargs="*")
    args = parser.parse_args()
    scan(args.recipe_paths, find_all=args.all)
