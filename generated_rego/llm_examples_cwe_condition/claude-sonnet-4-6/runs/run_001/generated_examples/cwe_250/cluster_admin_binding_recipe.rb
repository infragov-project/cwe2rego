# Chef recipe: bind service account to cluster-admin role

kubernetes_resource 'app-cluster-admin-binding' do
  resource_type 'ClusterRoleBinding'
  namespace 'default'
  config(
    'apiVersion' => 'rbac.authorization.k8s.io/v1',
    'kind' => 'ClusterRoleBinding',
    'metadata' => {
      'name' => 'app-cluster-admin-binding'
    },
    'roleRef' => {
      'apiGroup' => 'rbac.authorization.k8s.io',
      'kind' => 'ClusterRole',
      'name' => 'cluster-admin'
    },
    'subjects' => [
      {
        'kind' => 'ServiceAccount',
        'name' => 'app-service-account',
        'namespace' => 'default',
        'automountServiceAccountToken' => true
      }
    ]
  )
  action :apply
end

kubernetes_resource 'permissive-role' do
  resource_type 'ClusterRole'
  config(
    'apiVersion' => 'rbac.authorization.k8s.io/v1',
    'kind' => 'ClusterRole',
    'metadata' => { 'name' => 'permissive-role' },
    'rules' => [
      {
        'apiGroups' => ['*'],
        'resources' => ['*'],
        'verbs' => ['*']
      }
    ]
  )
  action :apply
end
