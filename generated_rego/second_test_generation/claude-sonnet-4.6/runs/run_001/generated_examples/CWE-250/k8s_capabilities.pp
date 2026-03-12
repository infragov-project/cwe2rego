class myapp::pod {
  kubernetes::resource::pod { 'excessive-caps-pod':
    ensure => present,
    metadata => {
      name => 'excessive-caps-pod',
      namespace => 'default',
    },
    spec => {
      containers => [
        {
          name  => 'app-container',
          image => 'nginx:latest',
          securityContext => {
            capabilities => {
              add => ['ALL'], # CWE-250: Excessive Linux capabilities
            },
          },
        },
      ],
    },
  }
}
