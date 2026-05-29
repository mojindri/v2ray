//! Xray `StatsService` gRPC implementation.

use std::collections::BTreeMap;

use blackwire_app::runtime_stats;
use tonic::{Request, Response, Status};

use crate::proto::stats_service_server::StatsService;
use crate::proto::{
    GetAllOnlineUsersRequest, GetAllOnlineUsersResponse, GetStatsOnlineIpListResponse,
    GetStatsRequest, GetStatsResponse, GetUsersStatsRequest, GetUsersStatsResponse, OnlineIpEntry,
    QueryStatsRequest, QueryStatsResponse, Stat, SysStatsRequest, SysStatsResponse,
    TrafficUserStat, UserStat,
};

/// Xray `StatsService` backed by [`blackwire_app::runtime_stats`].
#[derive(Default)]
pub struct StatsServiceImpl;

#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let req = request.into_inner();
        let value = runtime_stats::get(&req.name, req.reset).unwrap_or(0);
        Ok(Response::new(GetStatsResponse {
            stat: Some(Stat {
                name: req.name,
                value,
            }),
        }))
    }

    async fn get_stats_online(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        self.get_stats(request).await
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let req = request.into_inner();
        let stats = runtime_stats::query(&req.pattern, req.reset)
            .into_iter()
            .map(|(name, value)| Stat { name, value })
            .collect();
        Ok(Response::new(QueryStatsResponse { stat: stats }))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        let rss = runtime_stats::rss_bytes();
        Ok(Response::new(SysStatsResponse {
            num_goroutine: runtime_stats::num_tasks() as u32,
            num_gc: 0,
            alloc: rss,
            total_alloc: rss,
            sys: rss,
            mallocs: 0,
            frees: 0,
            live_objects: runtime_stats::num_threads(),
            pause_total_ns: 0,
            uptime: runtime_stats::uptime_secs(),
        }))
    }

    async fn get_stats_online_ip_list(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsOnlineIpListResponse>, Status> {
        let req = request.into_inner();
        Ok(Response::new(GetStatsOnlineIpListResponse {
            name: req.name,
            ips: Default::default(),
        }))
    }

    async fn get_all_online_users(
        &self,
        _request: Request<GetAllOnlineUsersRequest>,
    ) -> Result<Response<GetAllOnlineUsersResponse>, Status> {
        let mut users = BTreeMap::new();
        for (name, _) in runtime_stats::query("user>>>", false) {
            if let Some(user) = name
                .strip_prefix("user>>>")
                .and_then(|rest| rest.split(">>>").next())
            {
                users.insert(user.to_string(), ());
            }
        }
        Ok(Response::new(GetAllOnlineUsersResponse {
            users: users.into_keys().collect(),
        }))
    }

    async fn get_users_stats(
        &self,
        request: Request<GetUsersStatsRequest>,
    ) -> Result<Response<GetUsersStatsResponse>, Status> {
        let req = request.into_inner();
        let mut users: BTreeMap<String, UserStat> = BTreeMap::new();
        for (name, value) in runtime_stats::query("user>>>", req.reset) {
            let Some(rest) = name.strip_prefix("user>>>") else {
                continue;
            };
            let mut parts = rest.split(">>>");
            let Some(email) = parts.next() else {
                continue;
            };
            let direction = parts.nth(1).unwrap_or_default();
            let user = users.entry(email.to_string()).or_insert_with(|| UserStat {
                email: email.to_string(),
                ips: Vec::<OnlineIpEntry>::new(),
                traffic: Some(TrafficUserStat {
                    uplink: 0,
                    downlink: 0,
                }),
            });
            if let Some(traffic) = user.traffic.as_mut() {
                match direction {
                    "uplink" => traffic.uplink = value,
                    "downlink" => traffic.downlink = value,
                    _ => {}
                }
            }
        }

        Ok(Response::new(GetUsersStatsResponse {
            users: users.into_values().collect(),
        }))
    }
}
