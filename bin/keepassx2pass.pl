#!/usr/bin/env perl
use Modern::Perl;
#use Text::Iconv;
use File::Spec;
use lib ".";
use File::KeePass::Open qw(open_keepass);
use Data::Dumper;

my $filename = shift @ARGV;

my $keepass = open_keepass($filename);

$keepass->unlock;

sub command {
  my ($command, @lines) = @_;
  open(my $ph, qq{|$command}) or die "Can't fork $command: $!";
  for my $line (@lines) {
    say $ph $line;
  }
  close($ph) or die "$command returned error: $! $?";
}

sub strip {
  my $str = shift;
  $str =~ s/^\s*//;
  $str =~ s/\s*$//;
  return $str;
}

sub sanitize_title {
  my $title = shift;
  $title = strip($title);
  $title =~ s/[^\w.-]/_/g;
  $title =~ s/_+/_/g;
  return $title;
}

my %h;

sub import_entry {
  my ($entry, $path_so_far) = @_;
  print Dumper($entry);
  my $path = sanitize_title($entry->{title});
  my $full_path = $path_so_far ? File::Spec->catfile($path_so_far, $path) : $path;
  while (exists $h{$full_path}) {
    $full_path .= ('a'..'z')[rand(26)];
  }
  my @command = (qw(pass insert --multiline --force));
  push @command, $full_path;
  my @lines;
  push @lines, $entry->{password} || "";
  push @lines, "id: " . strip($entry->{username}) if $entry->{username} =~ /\S/;
  push @lines, "url: " . strip($entry->{url}) if $entry->{url} =~ /\S/;
  push @lines, strip($entry->{comment}) if $entry->{comment} =~ /\S/;
  my $command = join ' ', @command;
  command($command, @lines);
}

sub import_group {
  my ($group, $path_so_far) = @_;
  $path_so_far //= '';
  my $path = sanitize_title($group->{title});
  my $full_path = $path_so_far ? File::Spec->catfile($path_so_far, $path) : $path;
  for my $subgroup (@{$group->{groups}}) {
    import_group($subgroup, $full_path);
  }
  for my $entry (@{$group->{entries}}) {
    next if $entry->{title} eq 'Meta-Info';
    import_entry($entry, $path_so_far);
  }
}

my $group_list = $keepass->groups;

for my $group (@$group_list) {
  next if $group->{title} eq 'Backup';
  import_group($group);
}
