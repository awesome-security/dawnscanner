# Codesake Dawn - changelog

Dawn is a static analysis security scanner for ruby written web applications.
It supports [Sinatra](http://www.sinatrarb.com),
[Padrino](http://www.padrinorb.com) and [Ruby on Rails](http://rubyonrails.org)
frameworks. 

_latest update: Sun Jan  5 09:36:53 CET 2014_

## 

* Fixing issue #19 (https://github.com/codesake/codesake-dawn/issues/19). There
  was a problem on ```is_a_vulnerable_version?``` routine that flags a security
  check as vulnerable even if it wasn't. During the dependency check, if the
  vulnerable gem and the dependency has both major and minor version equal and
  the patch number tells if the gem is vulnerable or not, this check failed.
* Added a check for CVE-2004-0755
* Added a check for CVE-2004-0983
* Added a check for CVE-2005-1992
* Added a check for CVE-2005-2337
* Added a check for CVE-2006-1931
* Added a check for CVE-2006-2582
* Added a check for CVE-2006-3694
* Added a check for CVE-2006-4112
* Added a check for CVE-2006-5467
* Added a check for CVE-2006-6303


## Version 0.85 - codename: elevator (2013-12-17)

* refactoring bin/dawn script: some stuff were moved into Codesake::Core class
* Added a check against Denial of Service vulnerability for Nokogiri 1.5.x 
  and 1.6.0 when used with JRuby.
* Added a check against Denial of Service vulnerability due to entity expansion
  for Nokogiri 1.5.x and 1.6.0 when used with JRuby.
* Added a check for CVE-2013-4478 (sup remote code execution)
* Added a check for CVE-2013-4479 (sup remote code execution)
* Added a check for CVE-2013-1812 (ruby-openid denial of service)
* Added a check for CVE-2013-6421 (sprout remote code execution)



## Version 0.80 - codename: elevator (2013-12-12)

* adding test for CVE-2013-4164
* adding test for CVE-2013-4457
* adding test for CVE-2013-4562
* added a '-z' flag to exit the process with the number of issues found as exit code
* added a Cross Site Scripting in Simple Form gem
* adding test for CVE-2013-4492
* adding test for CVE-2013-4491
* adding test for CVE-2013-6414
* adding test for CVE-2013-6415
* adding test for CVE-2013-6416
* adding test for CVE-2013-6417

## Version 0.79.99 - codename:oddity (2013-11-14)

This is the first codesake-dawn version making codesake.com web application
able to scan something. It deserves a special release.

* adding test for CVE-2013-2065
* adding test for CVE-2013-4389
* adding test for CVE-2010-1330
* adding test for CVE-2011-0446 
* adding test for CVE-2011-0995
* adding test for CVE-2011-2929
* adding test for CVE-2011-4815
* adding test for CVE-2012-3424
* adding test for CVE-2012-5380
* adding test for CVE-2012-4522
* adding test for RoRCheatSheet\_1
* adding test for RoRCheatSheet\_4
* adding test for RoRCheatSheet\_7
* adding test for RoRCheatSheet\_8
* Fix issue #1. You can read more about it in TODO.md
* Added API to scan a single Gemfile.lock using -G flag

## Version 0.70 (2013-06-19)

* adding test for CVE-2011-0447
* adding test for CVE-2011-3186
* adding test for CVE-2012-1099
* adding test for CVE-2012-1241
* adding test for CVE-2012-2140
* adding test for CVE-2012-5370
* adding test for CVE-2012-5371
* adding test for CVE-2011-2197
* adding test for CVE-2011-2932
* adding test for CVE-2012-3463
* adding test for CVE-2012-3464
* adding test for CVE-2012-4464
* adding test for CVE-2012-4466
* adding test for CVE-2012-4481
* adding test for CVE-2012-6134
* Fix issue #4. PatternMatching complains when applied to binary files. We must
  skip them
* add ruby\_parser dependency
* add haml dependency
* add target MVC autodetect
* write '--help'
* detect sinks for XSS in Sinatra applications
* detect reflected XSS in Sinatra applications

## Version 0.60 (2013-05-28)

* adding cucumber dependency
* adding test for CVE-2013-1854
* adding test for CVE-2013-1856
* adding test for CVE-2013-0276
* adding test for CVE-2013-0277
* adding test for CVE-2013-0156
* adding test for CVE-2013-2615
* adding test for CVE-2013-1875
* adding test for CVE-2013-1655
* adding test for CVE-2013-1656
* adding test for CVE-2013-0175
* adding test for CVE-2013-0233
* adding test for CVE-2013-0284
* adding test for CVE-2013-0285
* adding test for CVE-2013-1801
* adding test for CVE-2013-1802
* adding test for CVE-2013-1821
* adding test for CVE-2013-1898
* adding test for CVE-2013-1911
* adding test for CVE-2013-1933
* adding test for CVE-2013-1947
* adding test for CVE-2013-1948
* adding test for CVE-2013-2616
* adding test for CVE-2013-2617
* adding test for CVE-2013-3221
* make output less verbose. Only vulnerabilities and severity will be shown 
* adding a '--verbose' option to see also the whole knowledge base info about each findings
* adding a '--output' option
* adding a '--count-only' option
* support JSON output

## Version 0.50 (2013-05-13) - First public release

* adding test for CVE\_2013\_0269
* adding test for CVE\_2013\_0155
* adding test for CVE\_2011\_2931
* adding test for CVE\_2012\_3465