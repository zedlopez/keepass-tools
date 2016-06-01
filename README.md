# keepass-tools

Tools to diff and merge Keepass databases, and to convert a keepass database to [pass](https://www.passwordstore.org/). It has only been used with Keepass v1 databases; since it depends on [File::KeePass](https://metacpan.org/pod/File::KeePass) which supports v2, it may work with v2 databases also.

File::Keepass::Diff depends on:
+ Modern::Perl
+ Exporter::Easy
+ File::KeePass

File::Keepass::Open depends on:
+ Exporter::Easy
+ File::KeePass
+ Term::ReadPassWord
+ Scalar::MoreUtils

Besides File::Keepass::Diff and File::Keepass::Open, keepass_diff.pl depends on:
+ Text::Table
+ Modern::Perl

Besides File::Keepass::Diff and File::Keepass::Open, keepass_merge.pl depends on:
+ Term::ReadLine
+ Term::ReadPassword

Besides File::Keepass::Open, keepassx2pass.pl depends on:
+ Modern::Perl


