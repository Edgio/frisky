frisky: Open souce code scanner
=================================

frisky is a simpler port of
[gitrob](https://github.com/michenriksen/gitrob) and is a command line
utility to scan codebases for sensitive files/contents.  It is
imagined this will happen as part of code review prior to open source
release.

frisky has some useful differences to gitrob:
 * single file, making distribution trivial
 * json output for integration with other utilities
 * ability to generate and consume and overrides file to suppress errors for specific matches
 * signature part 'contents' to analyze file contents
