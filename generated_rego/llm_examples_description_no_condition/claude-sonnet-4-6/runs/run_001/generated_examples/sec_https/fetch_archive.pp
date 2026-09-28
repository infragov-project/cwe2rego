class app::install (
  String $version = '3.1.0',
) {
  archive { "/tmp/app-${version}.tar.gz":
    ensure  => present,
    source  => "http://releases.example.com/app/${version}/app-${version}.tar.gz",
    extract => true,
    extract_path => '/opt/app',
    creates => "/opt/app/app-${version}",
    cleanup => true,
  }
}
