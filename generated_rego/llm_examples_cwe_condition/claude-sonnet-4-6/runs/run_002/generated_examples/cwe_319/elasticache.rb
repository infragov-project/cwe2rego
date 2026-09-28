#
# Cookbook:: cache
# Recipe:: elasticache
#

aws_elasticache_replication_group 'app-redis' do
  description                'Application Redis Cache'
  engine                     'redis'
  engine_version             '6.2.6'
  node_type                  'cache.t3.medium'
  num_cache_clusters         2
  port                       6379
  transit_encryption_enabled false
  at_rest_encryption_enabled false
  automatic_failover_enabled true
  action :create
end
