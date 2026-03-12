kubernetes_resource 'clusterrolebinding-admin-sa' do
  action :apply
  resource_type 'ClusterRoleBinding'
  resource_name 'admin-serviceaccount-binding'
  namespace 'default'
  apiVersion 'rbac.authorization.k8s.io/v1'
  data(
    subjects: [
      {
        kind: 'ServiceAccount',
        name: 'default',
        namespace: 'default',
      }
    ],
    roleRef: {
      kind: 'ClusterRole',
      name: 'cluster-admin', # CWE-250: Binding to cluster-admin role
      apiGroup: 'rbac.authorization.k8s.io',
    }
  )
end
