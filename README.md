# dns_deep_state

Find all secrets about DNS governing a domain

Setting up a domain name for proper hosting of a web site, emails or other
services can be quite counter-intuitive to people who are not familiar with how
this system all works.

Verifying that everything's been configured properly requires knowledge of many
tools and the nature of interactions between different systems.

This library aims to make it easier to run diagnostics and find where the
secret cabal that causes DNS malfunction is hiding.

## This project is still not solidified into something that can be documented

The internal and external interfaces are still in the process of being
designed. I'm slowly placing the design elements as things go since I didn't
have a great idea how to architect things from the start.

As soon as things start to make more sense, this file will get updated with
documentation on how to use the library and the CLI tool.

## Intentions

This project is a rewrite of a script I wrote for work and that had really poor
code quality.

The intention of this project is to avoid having to teach how to use the
multitude of tools for diagnosing a domain name's setup when helping out folks
with web/email hosting. All the information should be available in one place.
There's always at least one detail that slips by unnoticed when you need to use
4 or 5 different things.

The library aspect of this project will produce a JSON data structure that
contains information about the requested domain name, but also hints at things
that might be misconfigured.

The CLI should consume the JSON report and present the information in a
human-friendly way.

There might be more than one report in the future, but the first one that's
planned should contain information about domain registration (RDAP/whois), DNS
servers, Email DNS entries, and possible overrides in your local hosts
database.

With this information, it becomes easier to go from a question of the form "I'm
not getting any email and my website is not responding!" to "oh! your domain is
actually expired. is it possible that you forgot to pay for renewal? Your
domain is registered with XYZ"

It should help with weirder situations like "ah.. one of the DNS servers is
responding with a different zone serial number. that explains why your problem
is intermittent."

Once this first report is done, there can be more information added like
DNSSEC, CAA and other dns records of interest.

There should at some point also be some way to feed a list of "recognized
hosts" so that the CLI could identify where things are pointing to and whether
or not that's a problem in your context. e.g. "your website is pointing
directly to one of the web servers but it should really use the load balancer's
IP address."

stay tuned..
