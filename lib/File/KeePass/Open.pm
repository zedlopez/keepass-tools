package File::KeePass::Open;
use Exporter::Easy (OK => ['open_keepass']);
use File::KeePass;
use Term::ReadPassword;
use Scalar::MoreUtils qw(empty);

sub open_keepass {
  my $filename = shift;
  my $use_stars = shift // 1;
  die "No filename given" if empty $filename;
  die "filename is not a string" unless ref(\$filename) eq 'SCALAR';
  die "$filename doesn't exist" unless -e $filename;
  die "can't read $filename" unless -r $filename;
  die "$filename empty" unless -s $filename;
  {
    local $Term::ReadPassword::USE_STARS=$use_stars;
    $pw = read_password("Enter password for $filename: ");
  }
  my $keepass = File::KeePass->new;
  $keepass->load_db($filename, $pw); # load_db dies on error
  return $keepass;
}

1;
