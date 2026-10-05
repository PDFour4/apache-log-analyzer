# apache-log-analyzer

A Bash/awk tool that summarizes Apache `combined` access logs and emails a daily
report from cron. Written for a CMU 95-799 lab, then kept in production to
monitor the three sites on my home web server.

Read-only against the server: it reads logs and writes only under `$HOME`.
No credentials live in the script, and visitor IPs are masked before anything
leaves the machine.

## What the report contains

- The **30-second daily read**: a four-line checklist at the top of every email.
- Totals (requests, unique IPs, bytes), status classes, and top status codes.
- Top requested paths and client IPs, top 404 paths.
- **Suspicious probes**: requests for `.env`, `.git`, `wp-login.php`, `xmlrpc.php`,
  `phpmyadmin`, and friends, plus known scanner user agents. Includes a
  "probes that SUCCEEDED" line listing any sensitive path that returned 2xx.
- **Login POSTs** by IP and outcome, to spot password guessing and sign-ins.
- Top user agents, conversion-pixel counts for the marketing site, and
  cross-site visitor intersections (`comm`) when several sites are analyzed.

## Usage

```
log-analyzer.sh [-s minigolf|portal|portfolio|all] [-f /path/to/access.log]
                [-d today|yesterday] [-n 10] [--anonymize] [--mail] [--out file]
```

- `-s` maps a site name to its log under `$LOG_DIR` (default `/var/log/apache2`).
  Edit the `case` in `site_log()` for your own sites.
- `-f` analyzes any combined-format log, so it works on sample data too.
- `-d yesterday` reads the logrotate `*.log.1` file.
- `--anonymize` masks IPv4 last octets and IPv6 tails. It is forced on with `--mail`.
- No arguments: interactive prompts.

Portable across GNU awk and BSD awk; tested on Ubuntu 24.04 and macOS.
Verified with zero dropped lines on 384,428 lines of mixed real and sample logs.

## Mail

The server has no MTA, so the script speaks SMTP to Gmail with `curl`.
Create `~/.config/log-analyzer/mail.env` (chmod 600):

```
MAIL_FROM=you@gmail.com
MAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx     # Google App Password, spaces ok
MAIL_TO=you@gmail.com                     # optional, defaults to MAIL_FROM
```

The file is parsed as key=value lines, never sourced.

## Cron

```
0 6 * * * $HOME/bin/log-analyzer.sh -s all -d yesterday --mail >> $HOME/log-analyzer/cron.log 2>&1
```

## Sample output (anonymized, one site shown)

```
Apache Log Report  (generated 2026-10-04 20:53 EDT on webserver)
Covering: yesterday

-- The 30-second daily read --------------------------------------------
  1. "Probes that SUCCEEDED" says none on every site.
  2. "Login POSTs" is zero, or only your own IP prefix with a 302.
  3. The status class table has no 5xx line.
  4. Totals and top IPs look roughly like the day before.
  If all four hold, the day was normal. Everything else in the report is
  context for when one of them doesn't.
------------------------------------------------------------------------

######## minigolf ########
Log file: /var/log/apache2/access.log.1

== Totals ==
  Requests:        1983
  Unique IPs:      88
  Bytes sent:      5294997 (5.0 MB)
  First entry:     03/Oct/2026:00:10:08
  Last entry:      04/Oct/2026:00:18:58

== Responses by status class ==
  2xx        92  (  4.6%)
  3xx       506  ( 25.5%)
  4xx      1385  ( 69.8%)

== Top status codes ==
      1372  404
       502  301
        92  200
         6  405
         5  403

== Top 5 requested paths ==
        78  /
        14  /robots.txt
        14  /contact
        13  /v1/graphql
        13  /sitemap.xml

== Top 5 client IPs ==
       496  35.197.157.x
       337  34.146.254.x
       332  20.210.128.x
       259  20.194.30.x
       158  20.213.164.x

== Top 5 paths returning 404 ==
        13  /v1/graphql
        13  /sitemap.xml
        11  /robots.txt
         9  /.env
         8  /xmlrpc.php

== Suspicious probes (scanner paths / user agents) ==
  Probe requests:  1216
  Probing IPs:     26
  Top probed paths:
          10  /wp-login.php
          10  /wp-content/plugins/hellopress/wp_filemanager.php
          10  /.env
           8  /xmlrpc.php
           8  /this_is_a_new_hello_world.php
  Top probing IPs:
         332  20.210.128.x
         255  20.194.30.x
         154  35.197.157.x
         141  34.146.254.x
         140  20.213.164.x
  !! Probes that SUCCEEDED (2xx):
    (none)

== Login POSTs (password guessing / successful sign-ins) ==
  Login POSTs:     0
```
