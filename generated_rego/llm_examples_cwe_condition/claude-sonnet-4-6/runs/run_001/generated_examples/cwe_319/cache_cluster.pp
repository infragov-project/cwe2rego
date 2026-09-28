class cache_cluster (
  String  $cluster_id   = 'prod-redis-cluster',
  String  $node_type    = 'cache.t3.micro',
  Integer $num_nodes    = 2,
) {

  aws_elasticache_replication_group { $cluster_id:
    ensure                     => present,
    engine                     => 'redis',
    engine_version             => '6.x',
    node_type                  => $node_type,
    num_cache_clusters         => $num_nodes,
    automatic_failover_enabled => true,
    transit_encryption_enabled => false,
    at_rest_encryption_enabled => true,
    tls_enabled                => false,
    port                       => 6379,
  }
}
