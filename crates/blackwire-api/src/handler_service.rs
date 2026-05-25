//! Xray `HandlerService` gRPC (inbound/outbound tags and VLESS user ops).

use prost::Message;
use tonic::{Request, Response, Status};

use crate::handler_proto::handler_service_server::HandlerService;
use crate::handler_proto::{
    AddInboundRequest, AddInboundResponse, AddOutboundRequest, AddOutboundResponse,
    AddUserOperation, AlterInboundRequest, AlterInboundResponse, AlterOutboundRequest,
    AlterOutboundResponse, GetInboundUserRequest, GetInboundUserResponse,
    GetInboundUsersCountResponse, InboundHandlerConfig, ListInboundsRequest, ListInboundsResponse,
    ListOutboundsRequest, ListOutboundsResponse, OutboundHandlerConfig, RemoveInboundRequest,
    RemoveInboundResponse, RemoveOutboundRequest, RemoveOutboundResponse, RemoveUserOperation,
    TypedMessage, User,
};
use crate::management::ManagementHandle;
use crate::vless_account_proto::Account;

const ADD_USER_TYPE: &str = "xray.app.proxyman.command.AddUserOperation";
const REMOVE_USER_TYPE: &str = "xray.app.proxyman.command.RemoveUserOperation";

/// HandlerService backed by [`ManagementHandle`].
pub struct HandlerServiceImpl {
    management: ManagementHandle,
}

impl HandlerServiceImpl {
    /// Create a service using the shared runtime management handle.
    pub fn new(management: ManagementHandle) -> Self {
        Self { management }
    }
}

fn parse_vless_uuid_from_user(user: &User) -> Result<String, String> {
    let account = user
        .account
        .as_ref()
        .ok_or_else(|| "user.account is required for VLESS AddUser".to_string())?;
    if let Ok(acc) = Account::decode(account.value.as_slice()) {
        if !acc.id.is_empty() {
            return Ok(acc.id);
        }
    }
    if let Ok(text) = std::str::from_utf8(&account.value) {
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    Err("could not parse VLESS UUID from user.account".into())
}

#[tonic::async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn list_inbounds(
        &self,
        request: Request<ListInboundsRequest>,
    ) -> Result<Response<ListInboundsResponse>, Status> {
        let _only_tags = request.into_inner().is_only_tags;
        let inbounds = self
            .management
            .list_inbound_tags()
            .into_iter()
            .map(|tag| InboundHandlerConfig { tag })
            .collect();
        Ok(Response::new(ListInboundsResponse { inbounds }))
    }

    async fn get_inbound_users_count(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUsersCountResponse>, Status> {
        let req = request.into_inner();
        let count = self
            .management
            .vless_user_count(&req.tag)
            .ok_or_else(|| Status::not_found(format!("inbound '{}' not found", req.tag)))?;
        Ok(Response::new(GetInboundUsersCountResponse { count }))
    }

    async fn get_inbound_users(
        &self,
        request: Request<GetInboundUserRequest>,
    ) -> Result<Response<GetInboundUserResponse>, Status> {
        let req = request.into_inner();
        let records = self
            .management
            .list_vless_users(&req.tag, &req.email)
            .map_err(Status::failed_precondition)?;
        let users = records
            .into_iter()
            .map(|r| {
                let account_bytes = Account {
                    id: r.uuid,
                    flow: r.flow,
                    encryption: String::new(),
                }
                .encode_to_vec();
                User {
                    level: r.level,
                    email: r.email,
                    account: Some(TypedMessage {
                        r#type: "xray.proxy.vless.Account".into(),
                        value: account_bytes,
                    }),
                }
            })
            .collect();
        Ok(Response::new(GetInboundUserResponse { users }))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let req = request.into_inner();
        let op = req
            .operation
            .ok_or_else(|| Status::invalid_argument("operation is required"))?;
        let tag = req.tag;

        if op.r#type == ADD_USER_TYPE || op.r#type.ends_with("AddUserOperation") {
            let add = AddUserOperation::decode(op.value.as_slice())
                .map_err(|e| Status::invalid_argument(format!("AddUserOperation decode: {e}")))?;
            let user = add
                .user
                .ok_or_else(|| Status::invalid_argument("AddUserOperation.user is required"))?;
            let email = user.email.clone();
            let flow = user
                .account
                .as_ref()
                .and_then(|a| Account::decode(a.value.as_slice()).ok())
                .map(|a| a.flow)
                .unwrap_or_default();
            let uuid = parse_vless_uuid_from_user(&user).map_err(Status::invalid_argument)?;
            self.management
                .add_vless_user(&tag, &email, &uuid, &flow)
                .map_err(Status::failed_precondition)?;
            return Ok(Response::new(AlterInboundResponse {}));
        }

        if op.r#type == REMOVE_USER_TYPE || op.r#type.ends_with("RemoveUserOperation") {
            let remove = RemoveUserOperation::decode(op.value.as_slice()).map_err(|e| {
                Status::invalid_argument(format!("RemoveUserOperation decode: {e}"))
            })?;
            self.management
                .remove_vless_user(&tag, &remove.email)
                .map_err(Status::not_found)?;
            return Ok(Response::new(AlterInboundResponse {}));
        }

        Err(Status::unimplemented(format!(
            "unsupported AlterInbound operation type '{}'",
            op.r#type
        )))
    }

    async fn list_outbounds(
        &self,
        _request: Request<ListOutboundsRequest>,
    ) -> Result<Response<ListOutboundsResponse>, Status> {
        let outbounds = self
            .management
            .list_outbound_tags()
            .into_iter()
            .map(|tag| OutboundHandlerConfig { tag })
            .collect();
        Ok(Response::new(ListOutboundsResponse { outbounds }))
    }

    async fn add_inbound(
        &self,
        _request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        Err(Status::unimplemented(
            "AddInbound requires listener rebind; edit config.json and reload",
        ))
    }

    async fn remove_inbound(
        &self,
        _request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        Err(Status::unimplemented(
            "RemoveInbound requires instance restart",
        ))
    }

    async fn add_outbound(
        &self,
        _request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        Err(Status::unimplemented(
            "AddOutbound requires instance restart",
        ))
    }

    async fn remove_outbound(
        &self,
        _request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        Err(Status::unimplemented(
            "RemoveOutbound requires instance restart",
        ))
    }

    async fn alter_outbound(
        &self,
        _request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        Err(Status::unimplemented("AlterOutbound not implemented"))
    }
}
