#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import os
import re

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='Target file or directory to scan for XSS vulnerabilities', required=True)
args = parser.parse_args()

# Define regular expressions to search for potential XSS vulnerabilities
reflected_xss_re = re.compile(r'<\s*[A-Za-z]+\s+[^>]*[A-Za-z]+=([\'"]).*?\1[^>]*>')
stored_xss_re = re.compile(r'([^\w]|^)(\b(document|window|location|href)\b\s*=|\b(on\w+)=)([\'"]*)[^\n\'"]*?\5', re.IGNORECASE)
dom_based_xss_re = re.compile(r'(?<=<script)[^>]*>[^<]*<', re.IGNORECASE)

# Define a function to search for potential XSS vulnerabilities in a file
def search_for_xss_vulnerabilities(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        if content:
            potential_reflected_vulnerabilities = []
            for match in reflected_xss_re.findall(content):
                potential_reflected_vulnerabilities.append(match)

            potential_stored_vulnerabilities = []
            for match in stored_xss_re.findall(content):
                potential_stored_vulnerabilities.append(match[0])

            potential_dom_vulnerabilities = []
            for match in dom_based_xss_re.findall(content):
                potential_dom_vulnerabilities.append(match)

            if len(potential_reflected_vulnerabilities) > 0 or len(potential_stored_vulnerabilities) > 0 or len(potential_dom_vulnerabilities) > 0:
                print('Potential XSS vulnerabilities found in file: {}'.format(file_path))
                if len(potential_reflected_vulnerabilities) > 0:
                    print('\nReflected XSS vulnerabilities:')
                    for vulnerability in potential_reflected_vulnerabilities:
                        print(vulnerability)

                if len(potential_stored_vulnerabilities) > 0:
                    print('\nStored XSS vulnerabilities:')
                    for vulnerability in potential_stored_vulnerabilities:
                        print(vulnerability)

                if len(potential_dom_vulnerabilities) > 0:
                    print('\nDOM-based XSS vulnerabilities:')
                    for vulnerability in potential_dom_vulnerabilities:
                        print(vulnerability)
            else:
                print('No XSS vulnerabilities found in file: {}'.format(file_path))

# Check if the target is a file or directory
if os.path.isfile(args.target):
    search_for_xss_vulnerabilities(args.target)
elif os.path.isdir(args.target):
    vulnerabilities_found = False
    for dirpath, dirnames, filenames in os.walk(args.target):
        for filename in filenames:
            if filename.endswith('.html') or filename.endswith('.php'):
                file_path = os.path.join(dirpath, filename)
                search_for_xss_vulnerabilities(file_path)
                vulnerabilities_found = True

    if not vulnerabilities_found:
        print('No XSS vulnerabilities found on {}'.format(args.target))
