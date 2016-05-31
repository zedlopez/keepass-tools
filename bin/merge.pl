#!/usr/bin/env perl
use Modern::Perl;

use lib ".";
use File::KeePass::Open qw(open_keepass);
use File::KeePass::Diff qw(diff_keepass print_entry);
use Data::Dumper;
use File::Temp qw(tempfile);
use File::Copy;
use Term::ReadPassword;

my ($source1_path, $source2_path, $output_path, $print_password) = @ARGV;

die "Usage: $0 keepassdb1.kdb keepassdb2.kdb newkeepassdb.kdb" unless $source1_path and $source2_path and $output_path and $source1_path ne $source2_path and $source1_path ne $output_path and $source2_path ne $output_path;
die "$output_path already exists" if -e $output_path;

my $source1 = open_keepass($source1_path);
my $source2 = open_keepass($source2_path);

my $merged_password = read_password("Enter password for $output_path: ");
my $confirmed_merged_password = read_password("Confirm password for $output_path: ");

die "Passwords didn't match" unless $merged_password eq $confirmed_merged_password;

my $merged = File::KeePass->new;
my $merged_group = $merged->add_group({title => 'Passwords'});
my $term = Term::ReadLine->new('keepass_merge');

sub get_answer {
  my $prompt = shift;
  my $input;
  while (defined ($input = $term->readline("$prompt (y/n)? "))) {
    say "|$input|";
    last if $input =~ /^\s*[yn]/i;
  }
  return $input =~ /^\s*y/i;
}

my ($common, $only1, $only2, $differ) = diff_keepass($source1, $source1_path, $source2, $source2_path);

$merged->add_entry({ %{$_}, group => $merged_group}) for @$common, @$only1, @$only2;

if (@$differ) {
  for my $thrice (@$differ) {
    my ($entry1, $entry2, $difference) = @$thrice;
    say "Entries differ in ", (join ', ', keys %$difference), ':';
    say "${source1_path}'s version:";
    say "------------------------------------------";
    print_entry($entry1, undef, undef, $print_password);
    say "${source2_path}'s version:";
    say "------------------------------------------";
    print_entry($entry2, undef, undef, $print_password);
    my $name = $source1_path;
    my ($newer, $older) = ($entry1, $entry2);
    if ($entry1->{modified} lt $entry2->{modified}) {
      $name = $source2_path;
      ($newer, $older) = ($entry2, $entry1);
    }
    $merged->add_entry({ (get_answer("${name}'s is more recent. Keep it") ? %{$newer} : %{$older}), group => $merged_group});
  }
}
else {
  say "No entries differ between them."
}

my ($tmpfh, $tmpfilename) = tempfile();
$merged->save_db($tmpfilename, $merged_password);
open my $fh, '>', $output_path or die "Couldn't open $output_path for write: $!";
copy($tmpfilename, $fh);
