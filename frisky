#!/usr/bin/env python

# ----------------------------------------------------------------------------
# Copyright (C) 2017 Verizon.  All Rights Reserved.
# All Rights Reserved
#
#   Author: David Andrews
#   Date:   03/13/2017
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

# this script receives in a provided location, or cwd, and runs the regexes provided by
# gitrob_signatures.json, plus additional ones that are "part": "contents" to look for bad things

import json
import re
import sys
import os
import argparse

signatures = [
  {
      "part": "contents",
      "type": "regex",
      "pattern": "(url|host|host_?name|host_?addr|ip|ip_?addr|ip_?address)['\"]? ?[=:] ?['\"]((http|http)s?://)(1(?!(27|0|92)\\.)|[2-9]+)",
      "caption": "non RFC-1918 IP address",
      "description": None
  },
  {
      "part": "contents",
      "type": "regex",
      "pattern": "(password|passwd|pass|pwd)['\"]? ?[=:] ?['\"]?(?!(['\"]))",
      "caption": "static passwords",
      "description": None
  },
  {
      "part": "contents",
      "type": "regex",
      "pattern": "(\\..*\\.(net|com):(?!(80|443)\b))",
      "caption": "host names on non-http ports",
      "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A.*_rsa\\z",
    "caption": "Private SSH key",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A.*_dsa\\z",
    "caption": "Private SSH key",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A.*_ed25519\\z",
    "caption": "Private SSH key",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A.*_ecdsa\\z",
    "caption": "Private SSH key",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?ssh/config\\z",
    "caption": "SSH configuration file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "pem",
    "caption": "Potential cryptographic private key",
    "description": None
  },
  {
    "part": "extension",
    "type": "regex",
    "pattern": "\\Akey(pair)?\\z",
    "caption": "Potential cryptographic private key",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "pkcs12",
    "caption": "Potential cryptographic key bundle",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "pfx",
    "caption": "Potential cryptographic key bundle",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "p12",
    "caption": "Potential cryptographic key bundle",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "asc",
    "caption": "Potential cryptographic key bundle",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "otr.private_key",
    "caption": "Pidgin OTR private key",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?(bash_|zsh_|z)?history\\z",
    "caption": "Shell command history file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?mysql_history\\z",
    "caption": "MySQL client command history file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?psql_history\\z",
    "caption": "PostgreSQL client command history file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?pgpass\\z",
    "caption": "PostgreSQL password file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?irb_history\\z",
    "caption": "Ruby IRB console history file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?purple\\/accounts\\.xml\\z",
    "caption": "Pidgin chat client account configuration file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?xchat2?\\/servlist_?\\.conf\\z",
    "caption": "Hexchat/XChat IRC client server list configuration file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?irssi\\/config\\z",
    "caption": "Irssi IRC client configuration file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?recon-ng\\/keys\\.db\\z",
    "caption": "Recon-ng web reconnaissance framework API key database",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?dbeaver-data-sources.xml\\z",
    "caption": "DBeaver SQL database manager configuration file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?muttrc\\z",
    "caption": "Mutt e-mail client configuration file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?s3cfg\\z",
    "caption": "S3cmd configuration file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?aws/credentials\\z",
    "caption": "AWS CLI credentials file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?trc\\z",
    "caption": "T command-line Twitter client configuration file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "ovpn",
    "caption": "OpenVPN client configuration file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?gitrobrc\\z",
    "caption": "Well, this is awkward... Gitrob configuration file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?(bash|zsh)rc\\z",
    "caption": "Shell configuration file",
    "description": "Shell configuration files might contain information such as server hostnames, passwords and API keys."
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?(bash_|zsh_)?profile\\z",
    "caption": "Shell profile configuration file",
    "description": "Shell configuration files might contain information such as server hostnames, passwords and API keys."
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?(bash_|zsh_)?aliases\\z",
    "caption": "Shell command alias configuration file",
    "description": "Shell configuration files might contain information such as server hostnames, passwords and API keys."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "secret_token.rb",
    "caption": "Ruby On Rails secret token configuration file",
    "description": "If the Rails secret token is known, it can allow for remote code execution. (http://www.exploit-db.com/exploits/27527/)"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "omniauth.rb",
    "caption": "OmniAuth configuration file",
    "description": "The OmniAuth configuration file might contain client application secrets."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "carrierwave.rb",
    "caption": "Carrierwave configuration file",
    "description": "Can contain credentials for online storage systems such as Amazon S3 and Google Storage."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "schema.rb",
    "caption": "Ruby On Rails database schema file",
    "description": "Contains information on the database schema of a Ruby On Rails application."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "database.yml",
    "caption": "Potential Ruby On Rails database configuration file",
    "description": "Might contain database credentials."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "settings.py",
    "caption": "Django configuration file",
    "description": "Might contain database credentials, online storage system credentials, secret keys, etc."
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A(.*)?config(\\.inc)?\\.php\\z",
    "caption": "PHP configuration file",
    "description": "Might contain credentials and keys."
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "kdb",
    "caption": "KeePass password manager database file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "agilekeychain",
    "caption": "1Password password manager database file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "keychain",
    "caption": "Apple Keychain database file",
    "description": None
  },
  {
    "part": "extension",
    "type": "regex",
    "pattern": "\\Akey(store|ring)\\z",
    "caption": "GNOME Keyring database file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "log",
    "caption": "Log file",
    "description": "Log files might contain information such as references to secret HTTP endpoints, session IDs, user information, passwords and API keys."
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "pcap",
    "caption": "Network traffic capture file",
    "description": None
  },
  {
    "part": "extension",
    "type": "regex",
    "pattern": "\\Asql(dump)?\\z",
    "caption": "SQL dump file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "gnucash",
    "caption": "GnuCash database file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "backup",
    "caption": "Contains word: backup",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "dump",
    "caption": "Contains word: dump",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "password",
    "caption": "Contains word: password",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "credential",
    "caption": "Contains word: credential",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "secret",
    "caption": "Contains word: secret",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "private.*key",
    "caption": "Contains words: private, key",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml",
    "caption": "Jenkins publish over SSH plugin file",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "credentials.xml",
    "caption": "Potential Jenkins credentials file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?htpasswd\\z",
    "caption": "Apache htpasswd file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A(\\.|_)?netrc\\z",
    "caption": "Configuration file for auto-login process",
    "description": "Might contain username and password."
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "kwallet",
    "caption": "KDE Wallet Manager database file",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "LocalSettings.php",
    "caption": "Potential MediaWiki configuration file",
    "description": None
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "tblk",
    "caption": "Tunnelblick VPN configuration file",
    "description": None
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?gem/credentials\\z",
    "caption": "Rubygems credentials file",
    "description": "Might contain API key for a rubygems.org account."
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "Favorites.plist",
    "caption": "Sequel Pro MySQL database manager bookmark file",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "configuration.user.xpl",
    "caption": "Little Snitch firewall configuration file",
    "description": "Contains traffic rules for applications"
  },
  {
    "part": "extension",
    "type": "match",
    "pattern": "dayone",
    "caption": "Day One journal file",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "journal.txt",
    "caption": "Potential jrnl journal file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?tugboat\\z",
    "caption": "Tugboat DigitalOcean management tool configuration",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?git-credentials\\z",
    "caption": "git-credential-store helper credentials file",
    "description": None
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?gitconfig\\z",
    "caption": "Git configuration file",
    "description": None
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "knife.rb",
    "caption": "Chef Knife configuration file",
    "description": "Might contain references to Chef servers"
  },
  {
    "part": "path",
    "type": "regex",
    "pattern": "\\.?chef/(.*)\\.pem\\z",
    "caption": "Chef private key",
    "description": "Can be used to authenticate against Chef servers"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "proftpdpasswd",
    "caption": "cPanel backup ProFTPd credentials file",
    "description": "Contains usernames and password hashes for FTP accounts"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "robomongo.json",
    "caption": "Robomongo MongoDB manager configuration file",
    "description": "Might contain credentials for MongoDB databases"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "filezilla.xml",
    "caption": "FileZilla FTP configuration file",
    "description": "Might contain credentials for FTP servers"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "recentservers.xml",
    "caption": "FileZilla FTP recent servers file",
    "description": "Might contain credentials for FTP servers"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "ventrilo_srv.ini",
    "caption": "Ventrilo server configuration file",
    "description": "Might contain passwords"
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?dockercfg\\z",
    "caption": "Docker configuration file",
    "description": "Might contain credentials for public or private Docker registries"
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?npmrc\\z",
    "caption": "NPM configuration file",
    "description": "Might contain credentials for NPM registries"
  },
  {
    "part": "filename",
    "type": "match",
    "pattern": "terraform.tfvars",
    "caption": "Terraform variable config file",
    "description": "Might contain credentials for terraform providers"
  },
  {
    "part": "filename",
    "type": "regex",
    "pattern": "\\A\\.?env\\z",
    "caption": "Environment configuration file",
    "description": None
  }
]

parser = argparse.ArgumentParser(description="pre-receive oopsy checker",
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('PATH', type=str,
                    help='The directory to analyze')
parser.add_argument('--first', action='store_true',
                    help='Exit on the first file that violates our rules')
parser.add_argument('--match', action='store_true',
                    help='Print the matching value')
parser.add_argument('--no-colour', action='store_true',
                    help='No colour output.')
parser.add_argument('--override-filename', type=str, default=".frisky_overrides",
                    help='Filename holding JSON overrides for violations in the form: [{"path": "./path/to/my_dangerous_file.cc", "content": "totally_safe_ip = \\"123.111.0.0\\";"}...]')
parser.add_argument('--generate-overrides', action="store_true", help=argparse.SUPPRESS)
parser.add_argument('--warnings', action='store_true',
                    help='Print violations that have been overriden.')
parser.add_argument('--verbose', action='store_true',
                    help='Be noisy.  Implies --match and --warnings')
parser.add_argument('--json', action='store_true',
                    help='Produce JSON output.  Implies --no-colour, --warnings, overrides --verbose')
args = parser.parse_args()

if args.verbose:
    args.match = True
    args.warnings = True

if args.generate_overrides:
    args.json = True

# /// \brief   echo something in red
# /// \details
# /// \return
# /// \param   1 The string to print in red
# /// \status  ALPHA
def red(a_string):
    if not args.no_colour:
        return "\x1b[0;31m" + a_string + "\x1b[00m"
    else:
        return a_string


# /// \brief   echo something in cyan
# /// \details
# /// \return
# /// \param   1 The string to print in cyan
# /// \status  ALPHA
def cyan(a_string):
    if not args.no_colour:
        return "\x1b[0;36m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   echo something in green
# /// \details
# /// \return
# /// \param   1 The string to print in green
# /// \status  ALPHA
def green(a_string):
    if not args.no_colour:
        return "\x1b[0;32m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   echo something in yellow
# /// \details
# /// \return
# /// \param   1 The string to print in yellow
# /// \status  ALPHA
def yellow(a_string):
    if not args.no_colour:
        return "\x1b[0;33m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   echo something in white
# /// \details
# /// \return
# /// \param   1 The string to print in white
# /// \status  ALPHA
def white(a_string):
    if not args.no_colour:
        return "\x1b[0;37m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   echo something in underline
# /// \details
# /// \return
# /// \param   1 The string to print in white
# /// \status  ALPHA
def underline(a_string):
    if not args.no_colour:
        return "\x1b[0;4m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   echo something in bold
# /// \details
# /// \return
# /// \param   1 The string to print in white
# /// \status  ALPHA
def bold(a_string):
    if not args.no_colour:
        return "\x1b[0;1m" + a_string + "\x1b[00m"
    else:
        return a_string

# /// \brief   print something only if verbose
# /// \details
# /// \return  None
# /// \param   a_string The string to be printed (or not)
def verbose(a_string):
    if args.verbose:
        print a_string

# /// \brief   perform a match
# /// \details
# /// \return  The data that matched if it dide
# ///          None if no matches
# /// \param   a_data  The data to match against
# /// \param   a_pattern The pattern to run
# /// \param   a_type 'regex' or 'match' to regex or exact match data with pattern
def do_match(a_data, a_pattern, a_type):

    if a_type == "regex":
        match = re.compile(a_pattern, re.IGNORECASE).search(a_data)
        if match:
            return a_data.strip()
    elif a_type == "match":
        if a_data == a_pattern:
            return a_data
    else:
        print "Invalid type provided: '%s'."
    return None



# /// \brief   analyze a file
# /// \details
# /// \return  A list of the pattern violations from that file
# /// \param   a_path     The file path to analyze
def get_file_violations(a_subdir, a_filename):

    violations = []

    # for each object in the array
    for signature in signatures:
        #print signature

        l_data = ""
        if signature['part'] == "contents":

            l_contents = ""
            try:
                with open(os.path.join(a_subdir, a_filename), 'r') as content_file:
                    l_contents = content_file.readlines()
            except IOError, e:
                pass

            line = 1
            for l_data in l_contents:
                l_violations = do_match(l_data, signature['pattern'], signature['type'])
                if l_violations:
                    violations.append({ "data": l_violations, "signature": signature, "line_number": line} )
                line += 1

        else:

            if signature['part'] == "filename":
                l_data = a_filename
            elif signature['part'] == "extension":
                l_data = os.path.splitext(a_filename)[1][1:]
            elif signature['part'] == "path":
                l_data = os.path.join(a_subdir, a_filename)
            else:
                print "Unknown part: '%s'" % signature['part']

            l_violations = do_match(l_data, signature['pattern'], signature['type'])
            if l_violations:
                violations.append({ "data": l_violations, "signature": signature} )

    return violations


# /// \brief   analyze a file
# /// \details
# /// \return  A list of the pattern violations (including warnings) from that file
# /// \param   a_path     The file path to analyze
def get_violations(a_path):

    global is_fail
    os.chdir(a_path)

    # look for the optional ".frisky_overrides" in top level of a_path
    # JSON file that defines the file/content that is deemed sane to release
    # e.g. [{"path": "./path/to/my_dangerous_file.cc", "content": "totally_safe_ip = \"123.111.0.0\";"}, ...]
    overrides = []
    try:
        with open(os.path.join(args.override_filename), 'r') as override_file:
            overrides = json.load(override_file)
    except Exception, e:
        pass

    violations = []
    warnings = []
    for subdir, dirs, files in os.walk("."):
        if "/.git" in subdir:
            # don't process git directories
            continue
        for file in files:
            l_path = os.path.join(subdir, file)
            if file == ".frisky_overrides":
                continue
            verbose("Analyzing %s..." % (l_path))
            l_raw_violations = get_file_violations(subdir, file)
            l_warnings = []
            l_violations = []
            for idx,v in enumerate(l_raw_violations):

                is_warning = False
                for o in overrides:
                    if ("path" in o and
                        "content" in o and
                        o["path"] == l_path and
                        o["content"] == v["data"]):
                        l_warnings.append(v)
                        is_warning = True
                if not is_warning:
                    is_fail = True
                    l_violations.append(v)

            if (l_violations or
                l_warnings):
                violations.append({"path": l_path, "violations": l_violations, "warnings": l_warnings})

            if (l_violations and
                args.first):
                return (violations, warnings)

    return violations

is_fail = False

# walk the entire path
violations = get_violations(args.PATH)


if args.json:
    if args.generate_overrides:
        #Produce special output useul for the .frisky_overrides file
        sane = []
        for v in violations:
            for v_details in v["violations"]:
                #print k,v_details
                sane.append({"path": v["path"],
                             "content": v_details["data"]})
        print json.dumps(sane)
    else:
        print json.dumps(violations)
else:
    for v in violations:
        for v_details in v["violations"]:
            #print k,v_details
            if args.match:
                print "%s%s has %s %s %s matches pattern %s" % (v["path"],
                                                                ":" + str(v_details["line_number"]) if "line_number" in v_details else "",
                                                                yellow(v_details["signature"]["caption"]),
                                                                v_details["signature"]["part"],
                                                                red(v_details["data"]),
                                                                green(v_details["signature"]["pattern"]))
            else:
                print "%s%s has %s %s" % (v["path"],
                                          ":" + str(v_details["line_number"]) if "line_number" in v_details else "",
                                          yellow(v_details["signature"]["caption"]),
                                          v_details["signature"]["part"])
        if args.warnings:
            for v_details in v["warnings"]:
                #print k,v_details
                if args.match:
                    print "WARNING: %s%s has %s %s %s matches pattern %s" % (v["path"],
                                                                                ":" + str(v_details["line_number"]) if "line_number" in v_details else "",
                                                                                yellow(v_details["signature"]["caption"]),
                                                                                v_details["signature"]["part"],
                                                                                cyan(v_details["data"]),
                                                                                green(v_details["signature"]["pattern"]))
                else:
                    print "WARNING: %s%s has %s %s" % (v["path"],
                                                       ":" + str(v_details["line_number"]) if "line_number" in v_details else "",
                                                       yellow(v_details["signature"]["caption"]),
                                                       v_details["signature"]["part"])

# fail if violations found

sys.exit(1 if is_fail else 0)
