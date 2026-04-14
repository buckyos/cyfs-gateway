use super::server_err;
use crate::{
    HttpServer, NamedDataMgrRouteConfig, Server, ServerConfig, ServerContextRef, ServerError,
    ServerErrorCode, ServerFactory, ServerResult, StreamInfo,
};
use buckyos_kit::get_by_json_path;
use futures_util::TryStreamExt;
use http::{StatusCode, Version};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Bytes, Frame};
use named_store::{ChunkStoreState, NamedStoreMgr};
use ndm::{NamedDataMgr, PathKind};
use ndn_lib::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

/// Wrapper for ChunkReader to make it Sync
struct SyncChunkReader {
    reader: Arc<tokio::sync::Mutex<ChunkReader>>,
}

impl SyncChunkReader {
    fn new(reader: ChunkReader) -> Self {
        Self {
            reader: Arc::new(tokio::sync::Mutex::new(reader)),
        }
    }
}

impl tokio::io::AsyncRead for SyncChunkReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let mut reader = match self.reader.try_lock() {
            Ok(r) => r,
            Err(_) => {
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
        };
        let pinned_reader = std::pin::Pin::new(&mut *reader);
        pinned_reader.poll_read(cx, buf)
    }
}

/// Loaded object body types
enum LoadedObjBody {
    NamedObj(Value),              // JSON value, embedded obj_string
    Reader(SyncChunkReader, u64), // reader, chunk_size, embedded obj_string
    TextRecord(String),           // text_record, verify_obj path
}

/// Loaded object with metadata
struct LoadedObj {
    pub real_obj_id: Option<ObjId>,
    pub real_body: LoadedObjBody,
    pub path_obj_jwt: Option<String>,
}

impl LoadedObj {
    pub fn new_chunk_result(real_obj_id: ObjId, real_body: ChunkReader, chunk_size: u64) -> Self {
        let body = LoadedObjBody::Reader(SyncChunkReader::new(real_body), chunk_size);
        Self {
            real_obj_id: Some(real_obj_id),
            real_body: body,
            path_obj_jwt: None,
        }
    }

    pub fn new_named_obj_result(real_obj_id: ObjId, real_body: Value) -> Self {
        let body = LoadedObjBody::NamedObj(real_body);
        Self {
            real_obj_id: Some(real_obj_id),
            real_body: body,
            path_obj_jwt: None,
        }
    }

    pub fn new_value_result(real_obj_id: Option<ObjId>, real_body: Value) -> Self {
        let body_str = serde_json::to_string(&real_body).unwrap();
        let body = LoadedObjBody::TextRecord(body_str);

        Self {
            real_obj_id: real_obj_id,
            real_body: body,
            path_obj_jwt: None,
        }
    }
}

/// Inner path information
pub struct InnerPathInfo {
    pub root_obj_id: ObjId,
    pub inner_obj_path: String,
    pub inner_proof: Option<String>,
}

/// Load object directly from NamedStoreMgr
async fn load_obj(
    store_mgr: Arc<NamedStoreMgr>,
    obj_id: &ObjId,
    offset: u64,
) -> ServerResult<LoadedObj> {
    if obj_id.is_chunk() {
        let chunk_id = ChunkId::from_obj_id(obj_id);
        let (chunk_reader, chunk_size) = store_mgr
            .open_chunk_reader(&chunk_id, offset)
            .await
            .map_err(|e| {
                warn!("get chunk reader by objid failed: {}", e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(
                        ServerErrorCode::IOError,
                        "get chunk reader by objid failed: {}",
                        e
                    ),
                }
            })?;

        debug!(
            "ndn server -> chunk: {}, chunk_size: {}, offset: {}",
            obj_id.to_base32(),
            chunk_size,
            offset
        );
        return Ok(LoadedObj::new_chunk_result(
            obj_id.clone(),
            chunk_reader,
            chunk_size,
        ));
    } else if obj_id.is_chunk_list() {
        let (chunk_list_reader, chunk_list_size) = store_mgr
            .open_chunklist_reader(obj_id, offset)
            .await
            .map_err(|e| {
                warn!("get chunk list reader by objid failed: {}", e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(
                        ServerErrorCode::IOError,
                        "get chunk list reader by objid failed: {}",
                        e
                    ),
                }
            })?;

        debug!(
            "ndn server -> chunk list: {}, chunk list size: {}, offset: {}",
            obj_id.to_base32(),
            chunk_list_size,
            offset
        );
        return Ok(LoadedObj::new_chunk_result(
            obj_id.clone(),
            chunk_list_reader,
            chunk_list_size,
        ));
    } else {
        let obj_body_str = store_mgr.get_object(obj_id).await.map_err(|e| {
            warn!("get object by objid failed: {}", e);
            match e {
                NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                _ => server_err!(
                    ServerErrorCode::IOError,
                    "get object by objid failed: {}",
                    e
                ),
            }
        })?;
        let obj_body = load_named_object_from_obj_str(obj_body_str.as_str()).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidData,
                "Failed to parse object {}: {}",
                obj_id,
                e
            )
        })?;
        debug!("ndn server -> obj {}", obj_body.to_string());
        return Ok(LoadedObj::new_named_obj_result(obj_id.clone(), obj_body));
    }
}

/// Build HTTP response from loaded object
async fn build_response_by_obj_get_result(
    obj_load_result: LoadedObj,
    start: u64,
    inner_path_info: Option<InnerPathInfo>,
) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
    let body_result;
    let mut result = http::Response::builder();
    debug!(
        "ndn_server: build_response_by_obj_get_result: obj_load_result: {:?}",
        obj_load_result.real_obj_id
    );

    if obj_load_result.real_obj_id.is_some() {
        result = result.header(
            "cyfs-obj-id",
            obj_load_result.real_obj_id.unwrap().to_base32(),
        );
    }

    if inner_path_info.is_some() {
        let inner_path_info = inner_path_info.unwrap();
        result = result.header("cyfs-root-obj-id", inner_path_info.root_obj_id.to_base32());

        if inner_path_info.inner_proof.is_some() {
            result = result.header("cyfs-proof", inner_path_info.inner_proof.unwrap());
        }
    }

    if obj_load_result.path_obj_jwt.is_some() {
        result = result.header("cyfs-path-obj", obj_load_result.path_obj_jwt.unwrap());
    }

    match obj_load_result.real_body {
        LoadedObjBody::NamedObj(json_value) => {
            result = result
                .header("Content-Type", "application/json")
                .status(StatusCode::OK);
            body_result = result
                .body(
                    Full::new(Bytes::from(serde_json::to_string(&json_value).map_err(
                        |e| {
                            server_err!(
                                ServerErrorCode::EncodeError,
                                "Failed to convert json value to string: {}",
                                e
                            )
                        },
                    )?))
                    .map_err(|never| match never {})
                    .boxed(),
                )
                .unwrap();
        }
        LoadedObjBody::Reader(chunk_reader, chunk_size) => {
            let stream = tokio_util::io::ReaderStream::new(chunk_reader);
            result = result
                .header("Accept-Ranges", "bytes")
                .header("Content-Type", "application/octet-stream")
                .header("Cache-Control", "public,max-age=31536000")
                .header("cyfs-obj-size", chunk_size.to_string());

            if start > 0 {
                debug!(
                    "ndn_server: build_response_by_obj_get_result: Content-Range: bytes {}-{}/{}",
                    start,
                    chunk_size - 1,
                    chunk_size
                );
                result = result
                    .header(
                        "Content-Range",
                        format!("bytes {}-{}/{}", start, chunk_size - 1, chunk_size),
                    )
                    .header("Content-Length", chunk_size - start)
                    .status(StatusCode::PARTIAL_CONTENT);
            } else {
                debug!(
                    "ndn_server: build_response_by_obj_get_result: Content-Length: {}",
                    chunk_size
                );
                result = result
                    .header("Content-Length", chunk_size)
                    .status(StatusCode::OK);
            }
            let stream_body = StreamBody::new(stream.map_ok(Frame::data));
            body_result = result
                .body(
                    BodyExt::map_err(stream_body, |e| {
                        ServerError::new(
                            ServerErrorCode::StreamError,
                            format!("Stream error: {}", e),
                        )
                    })
                    .boxed(),
                )
                .unwrap();
        }
        LoadedObjBody::TextRecord(text_record) => {
            result = result
                .header("Content-Type", "plain/text")
                .status(StatusCode::OK);
            body_result = result
                .body(
                    Full::new(Bytes::from(text_record))
                        .map_err(|never| match never {})
                        .boxed(),
                )
                .unwrap();
        }
    }
    Ok(body_result)
}

/// Parse range header
fn parse_range(range_str: &str, max_size: u64) -> ServerResult<(u64, u64)> {
    let range_str = range_str.trim();
    if !range_str.starts_with("bytes=") {
        return Err(server_err!(
            ServerErrorCode::BadRequest,
            "Invalid range header"
        ));
    }

    let range_str = &range_str[6..];
    let parts: Vec<&str> = range_str.split('-').collect();

    if parts.len() != 2 {
        return Err(server_err!(
            ServerErrorCode::BadRequest,
            "Invalid range format"
        ));
    }

    let start = if parts[0].is_empty() {
        0
    } else {
        parts[0]
            .parse::<u64>()
            .map_err(|_| server_err!(ServerErrorCode::BadRequest, "Invalid range start"))?
    };

    let end = if parts[1].is_empty() {
        max_size
    } else {
        parts[1]
            .parse::<u64>()
            .map_err(|_| server_err!(ServerErrorCode::BadRequest, "Invalid range end"))?
    };

    Ok((start, end))
}

/// NdnServer Builder for fluent configuration
pub struct NdnServerBuilder {
    id: Option<String>,
    version: Option<String>,
    config: Option<NamedDataMgrRouteConfig>,
}

impl NdnServerBuilder {
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn config(mut self, config: NamedDataMgrRouteConfig) -> Self {
        self.config = Some(config);
        self
    }

    pub async fn build(self) -> ServerResult<NdnServer> {
        NdnServer::create_server(self).await
    }
}

/// NdnServer - Named Data Network server that serves NDN objects
pub struct NdnServer {
    id: String,
    version: http::Version,
    config: NamedDataMgrRouteConfig,
    store_mgr: Arc<NamedStoreMgr>,
}

impl NdnServer {
    pub fn builder() -> NdnServerBuilder {
        NdnServerBuilder {
            id: None,
            version: None,
            config: None,
        }
    }

    async fn create_server(builder: NdnServerBuilder) -> ServerResult<NdnServer> {
        if builder.id.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "id is required"
            ));
        }

        if builder.config.is_none() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "config is required"
            ));
        }

        let version: http::Version = match builder.version {
            Some(ref version) => match version.as_str() {
                "HTTP/0.9" => http::Version::HTTP_09,
                "HTTP/1.0" => http::Version::HTTP_10,
                "HTTP/1.1" => http::Version::HTTP_11,
                "HTTP/2" => http::Version::HTTP_2,
                "HTTP/3" => http::Version::HTTP_3,
                _ => {
                    return Err(server_err!(
                        ServerErrorCode::InvalidConfig,
                        "invalid http version"
                    ));
                }
            },
            None => http::Version::HTTP_11,
        };

        let config = builder.config.unwrap();
        let store_config_path = config.named_store_config_path.trim();
        if store_config_path.is_empty() {
            return Err(server_err!(
                ServerErrorCode::InvalidConfig,
                "named_store_config_path is required"
            ));
        }

        let store_mgr = Arc::new(
            NamedStoreMgr::get_store_mgr(Path::new(store_config_path))
                .await
                .map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidConfig,
                        "Failed to open named store config {}: {}",
                        store_config_path,
                        e
                    )
                })?,
        );

        Ok(NdnServer {
            id: builder.id.unwrap(),
            version,
            config,
            store_mgr,
        })
    }

    async fn get_default_named_mgr(&self) -> ServerResult<Arc<tokio::sync::Mutex<NamedDataMgr>>> {
        NamedDataMgr::get_named_data_mgr_by_id(None)
            .await
            .ok_or_else(|| {
                server_err!(
                    ServerErrorCode::NotFound,
                    "Default named data manager not found"
                )
            })
    }

    /// Handle chunk PUT request
    async fn handle_chunk_put(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        if self.config.read_only {
            error!("Named manager is read only, can't process put");
            return Err(server_err!(
                ServerErrorCode::Rejected,
                "Named manager is read only"
            ));
        }

        if !self.config.enable_zone_put_chunk {
            error!("Named manager is not enable zone put chunk");
            return Err(server_err!(
                ServerErrorCode::Rejected,
                "Named manager is not enable zone put chunk"
            ));
        }

        let path = req.uri().path();
        let obj_id = match ObjId::from_path(path) {
            Ok((id, _)) => id,
            Err(_) => {
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "Invalid object ID in path"
                ));
            }
        };

        let chunk_id = ChunkId::from_obj_id(&obj_id);

        // Get total size
        let total_size = req
            .headers()
            .get("cyfs-chunk-size")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Read entire request body to memory
        let body_bytes = req
            .collect()
            .await
            .map_err(|e| {
                server_err!(
                    ServerErrorCode::BadRequest,
                    "Failed to read request body: {}",
                    e
                )
            })?
            .to_bytes();

        let body_size = body_bytes.len() as u64;
        if total_size != 0 && total_size != body_size {
            return Err(server_err!(
                ServerErrorCode::BadRequest,
                "Chunk size mismatch, header={}, body={}",
                total_size,
                body_size
            ));
        }

        self.store_mgr
            .put_chunk(&chunk_id, body_bytes.as_ref(), false)
            .await
            .map_err(|e| {
                warn!("Failed to store chunk: {}", e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(ServerErrorCode::IOError, "Failed to store chunk: {}", e),
                }
            })?;

        return Ok(http::Response::builder()
            .status(StatusCode::OK)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }

    /// Handle chunk status request (HEAD)
    async fn handle_chunk_status(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let path = req.uri().path();
        let obj_id = match ObjId::from_path(path) {
            Ok((id, _)) => id,
            Err(_) => {
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "Invalid object ID in path"
                ));
            }
        };

        let chunk_id = ChunkId::from_obj_id(&obj_id);

        let (chunk_state, chunk_size, progress) = self
            .store_mgr
            .query_chunk_state(&chunk_id)
            .await
            .map_err(|e| {
                warn!("Failed to query chunk state: {}", e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(
                        ServerErrorCode::IOError,
                        "Failed to query chunk state: {}",
                        e
                    ),
                }
            })?;

        let status_code = match chunk_state {
            ChunkStoreState::New => StatusCode::CREATED,
            ChunkStoreState::Completed => StatusCode::OK,
            ChunkStoreState::Incompleted => StatusCode::PARTIAL_CONTENT,
            ChunkStoreState::Disabled => StatusCode::FORBIDDEN,
            ChunkStoreState::NotExist => StatusCode::NOT_FOUND,
            ChunkStoreState::LocalLink(_) => StatusCode::OK,
        };

        return Ok(http::Response::builder()
            .status(status_code)
            .header("Content-Length", chunk_size.to_string())
            .header("cyfs-chunk-status", chunk_state.to_str())
            .header("cyfs-chunk-progress", progress)
            .body(
                Full::new(Bytes::new())
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap());
    }

    /// Handle NDN GET request
    async fn handle_ndn_get(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        host: &str,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let range_str = req.headers().get(hyper::header::RANGE);
        let mut start = 0;
        let mut _end = u64::MAX;
        if range_str.is_some() {
            let range_str = range_str.unwrap().to_str().unwrap();
            (start, _end) = parse_range(range_str, u64::MAX)?;
        }

        let req_path = req.uri().path();
        let mut obj_id: Option<ObjId> = None;
        let path_obj_jwt: Option<String> = None;

        let mut root_obj_id: Option<ObjId> = None;
        let mut _inner_obj_path: Option<String> = None;
        let inner_path_info: Option<InnerPathInfo>;

        // Get objid by hostname
        let obj_id_result = ObjId::from_hostname(host);
        if obj_id_result.is_ok() {
            obj_id = Some(obj_id_result.unwrap());
        }

        if obj_id.is_none() && self.config.is_object_id_in_path {
            let obj_id_result = ObjId::from_path(req_path);
            if obj_id_result.is_ok() {
                let (the_obj_id, the_obj_path) = obj_id_result.unwrap();
                if the_obj_path.is_some() {
                    debug!("get root object_id and inner_path from url");
                    _inner_obj_path = the_obj_path;
                    root_obj_id = Some(the_obj_id);
                } else {
                    debug!("get object id from url");
                    obj_id = Some(the_obj_id);
                }
            }
        }

        if obj_id.is_none() && self.config.enable_mgr_file_path {
            let sub_path = NdmPath::new(req_path.to_string());
            let named_mgr = self.get_default_named_mgr().await?;
            let real_named_mgr = named_mgr.lock().await;
            let stat = real_named_mgr.stat(&sub_path).await.map_err(|e| {
                warn!("ndn_server: stat failed for {}: {}", sub_path.as_str(), e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(
                        ServerErrorCode::IOError,
                        "ndn_server: stat failed for {}: {}",
                        sub_path.as_str(),
                        e
                    ),
                }
            })?;

            if stat.kind != PathKind::NotFound {
                if let Some(stat_obj_id) = stat.obj_id {
                    if let Some(the_inner_path) = stat.obj_inner_path {
                        debug!(
                            "ndn_server: stat success, ndn_path: {}, obj_inner_path: {}",
                            sub_path.as_str(),
                            the_inner_path
                        );
                        if stat_obj_id.is_chunk() {
                            return Err(server_err!(
                                ServerErrorCode::BadRequest,
                                "ndn_server: chunk is not supported to be root obj"
                            ));
                        }
                        if stat_obj_id.is_big_container() {
                            warn!("ndn_server: big container is not supported to be root obj");
                            return Err(server_err!(
                                ServerErrorCode::BadRequest,
                                "ndn_server: big container is not supported to be root obj"
                            ));
                        }
                        _inner_obj_path = Some(the_inner_path);
                        root_obj_id = Some(stat_obj_id);
                    } else {
                        debug!("ndn_server: stat success, ndn_path: {}", sub_path.as_str());
                        obj_id = Some(stat_obj_id);
                    }
                } else {
                    debug!(
                        "ndn_server: stat resolved path {} as {:?} without obj_id",
                        sub_path.as_str(),
                        stat.kind
                    );
                }
            }
        }

        if obj_id.is_none() && root_obj_id.is_none() {
            warn!(
                "ndn_server: can't get obj id from request!, request.uri(): {}",
                req.uri()
            );
            return Err(server_err!(
                ServerErrorCode::NotFound,
                "NotFound! failed to get obj id from request!, request.uri(): {}",
                req.uri()
            ));
        }

        debug!(
            "ndn_server will load object, obj_id: {:?}, root_obj_id: {:?}",
            obj_id, root_obj_id
        );

        // Load obj
        if _inner_obj_path.is_some() {
            let root_obj_id = root_obj_id.unwrap();
            let inner_obj_path = _inner_obj_path.unwrap();
            let root_obj_str = self.store_mgr.get_object(&root_obj_id).await.map_err(|e| {
                warn!("Failed to get object: {}", e);
                match e {
                    NdnError::NotFound(e2) => server_err!(ServerErrorCode::NotFound, "{}", e2),
                    _ => server_err!(ServerErrorCode::IOError, "Failed to get object: {}", e),
                }
            })?;
            let root_obj_json =
                load_named_object_from_obj_str(root_obj_str.as_str()).map_err(|e| {
                    server_err!(
                        ServerErrorCode::InvalidData,
                        "Failed to parse object {}: {}",
                        root_obj_id,
                        e
                    )
                })?;

            let obj_filed = get_by_json_path(&root_obj_json, &inner_obj_path);
            if obj_filed.is_none() {
                warn!(
                    "ndn_server: can't found target object, inner_obj_path {} is not valid",
                    &inner_obj_path
                );
                return Err(server_err!(
                    ServerErrorCode::BadRequest,
                    "ndn_server: can't found target object, inner_obj_path is not valid"
                ));
            }

            // This is the target content or target obj_id
            inner_path_info = Some(InnerPathInfo {
                root_obj_id: root_obj_id,
                inner_obj_path: inner_obj_path,
                inner_proof: None,
            });

            let obj_filed = obj_filed.unwrap();
            if obj_filed.is_string() {
                let obj_id_str = obj_filed.as_str().unwrap();
                let p_obj_id = ObjId::new(obj_id_str);
                if p_obj_id.is_ok() {
                    obj_id = Some(p_obj_id.unwrap());
                }
            }

            if obj_id.is_none() {
                // Return root_obj's field
                let mut load_result = LoadedObj::new_value_result(None, obj_filed);
                load_result.path_obj_jwt = path_obj_jwt;
                let response =
                    build_response_by_obj_get_result(load_result, start, inner_path_info).await?;
                return Ok(response);
            }
        } else {
            inner_path_info = None;
        }

        debug!("ndn_server: obj_id: {:?}", obj_id);
        let obj_id = obj_id.unwrap();
        debug!("ndn_server: before load obj");
        let mut load_result: LoadedObj = load_obj(self.store_mgr.clone(), &obj_id, start).await?;
        load_result.path_obj_jwt = path_obj_jwt;
        let response = build_response_by_obj_get_result(load_result, start, inner_path_info)
            .await
            .map_err(|e| {
                warn!("ndn_server: build_response_by_obj_get_result failed: {}", e);
                e
            })?;
        debug!("ndn_server: build_response_by_obj_get_result success");
        return Ok(response);
    }
}

#[async_trait::async_trait]
impl HttpServer for NdnServer {
    async fn serve_request(
        &self,
        req: http::Request<BoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<BoxBody<Bytes, ServerError>>> {
        let req_path = req.uri().path().to_string();
        let req_method = req.method().clone();
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("localhost")
            .to_string();

        debug!(
            "NdnServer[{}] {} {} from {:?}",
            self.id, req_method, req_path, info.src_addr
        );

        if req_method == hyper::Method::PUT || req_method == hyper::Method::PATCH {
            return self.handle_chunk_put(req).await;
        }

        if req_method == hyper::Method::HEAD {
            return self.handle_chunk_status(req).await;
        }

        if req_method == hyper::Method::GET {
            return self.handle_ndn_get(req, &host).await;
        }

        warn!("Method not allowed: {}", req_method);
        return Ok(http::Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(
                Full::new(Bytes::from("Method not allowed"))
                    .map_err(|e| match e {})
                    .boxed(),
            )
            .unwrap());
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn http_version(&self) -> Version {
        self.version
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }
}

/// Configuration for NdnServer
#[derive(Serialize, Deserialize, Clone)]
pub struct NdnServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub named_mgr: NamedDataMgrRouteConfig,
}

impl ServerConfig for NdnServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "ndn".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

/// Factory for creating NdnServer instances
pub struct NdnServerFactory;

#[async_trait::async_trait]
impl ServerFactory for NdnServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        _context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config_json = config.get_config_json();
        let ndn_config: NdnServerConfig = serde_json::from_str(&config_json).map_err(|e| {
            server_err!(
                ServerErrorCode::InvalidConfig,
                "Failed to parse NdnServerConfig: {}",
                e
            )
        })?;

        let server = NdnServer::builder()
            .id(ndn_config.id)
            .version(ndn_config.version.unwrap_or_else(|| "HTTP/1.1".to_string()))
            .config(ndn_config.named_mgr)
            .build()
            .await?;

        Ok(vec![Server::Http(Arc::new(server))])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    // Helper function to create a temporary directory with a minimal NamedStoreMgr config.
    fn create_test_named_data_mgr() -> (TempDir, NamedDataMgrRouteConfig) {
        let temp_dir = TempDir::new().unwrap();
        let store_config_path = temp_dir.path().join("named_store.json");
        let store_root = temp_dir.path().join("store");
        fs::write(
            &store_config_path,
            serde_json::json!({
                "stores": [
                    { "path": store_root.to_string_lossy() }
                ]
            })
            .to_string(),
        )
        .unwrap();

        let config = NamedDataMgrRouteConfig {
            named_store_config_path: store_config_path.to_string_lossy().to_string(),
            read_only: false,
            guest_access: true,
            is_object_id_in_path: true,
            enable_mgr_file_path: true,
            enable_zone_put_chunk: true,
        };
        (temp_dir, config)
    }

    #[test]
    fn test_ndn_server_config_serialization() {
        let config = NdnServerConfig {
            id: "test_ndn".to_string(),
            ty: "ndn".to_string(),
            version: Some("HTTP/1.1".to_string()),
            named_mgr: NamedDataMgrRouteConfig::default(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: NdnServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.id, deserialized.id);
    }

    #[tokio::test]
    async fn test_create_server_without_id() {
        let (_temp_dir, mgr_config) = create_test_named_data_mgr();

        let result = NdnServer::builder().config(mgr_config).build().await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_without_config() {
        let result = NdnServer::builder().id("test").build().await;
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.code(), ServerErrorCode::InvalidConfig);
        }
    }

    #[tokio::test]
    async fn test_create_server_with_valid_config() {
        let (_temp_dir, mgr_config) = create_test_named_data_mgr();

        let result = NdnServer::builder()
            .id("test")
            .config(mgr_config)
            .build()
            .await;

        assert!(result.is_ok());
    }

    // #[tokio::test]
    // async fn test_put_chunk_success() {
    //     // 创建临时目录和配置
    //     let (_temp_dir, mgr_config) = create_test_named_data_mgr();
    //
    //     // 创建服务器
    //     let server = Arc::new(
    //         NdnServer::builder()
    //             .id("test")
    //             .config(mgr_config)
    //             .build()
    //             .await
    //             .unwrap(),
    //     );
    //
    //     let (client, server_stream) = tokio::io::duplex(1024);
    //
    //     // 启动服务器
    //     tokio::spawn(async move {
    //         hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
    //             .await
    //             .unwrap();
    //     });
    //
    //     // 创建一个测试chunk ID
    //     let chunk_data = b"Hello, World! This is test chunk data for NDN server PUT test.";
    //     let chunk_hasher = ChunkHasher::new(None).unwrap();
    //     let chunk_id = chunk_hasher.calc_mix_chunk_id_from_bytes(chunk_data).unwrap();
    //
    //     // 构造PUT请求
    //     let request = http::Request::builder()
    //         .method("PUT")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .header("cyfs-chunk-size", chunk_data.len().to_string())
    //         .body(Full::new(Bytes::from(chunk_data.to_vec())))
    //         .unwrap();
    //
    //     // 发送请求
    //     let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //         .handshake(TokioIo::new(client))
    //         .await
    //         .unwrap();
    //
    //     tokio::spawn(async move {
    //         conn.await.unwrap();
    //     });
    //
    //     let resp = sender.send_request(request).await.unwrap();
    //     // PUT操作应该成功
    //     assert_eq!(resp.status(), StatusCode::OK);
    // }
    //
    // #[tokio::test]
    // async fn test_put_chunk_readonly() {
    //     // 创建只读配置
    //     let (_temp_dir, mut mgr_config) = create_test_named_data_mgr();
    //     mgr_config.read_only = true;
    //
    //     // 创建服务器
    //     let server = Arc::new(
    //         NdnServer::builder()
    //             .id("test")
    //             .config(mgr_config)
    //             .build()
    //             .await
    //             .unwrap(),
    //     );
    //
    //     let (client, server_stream) = tokio::io::duplex(1024);
    //
    //     // 启动服务器
    //     tokio::spawn(async move {
    //         hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
    //             .await
    //             .unwrap();
    //     });
    //
    //     // 创建一个测试chunk ID
    //     let chunk_data = b"Hello, World! This is test chunk data for NDN server PUT test.";
    //     let chunk_hasher = ChunkHasher::new(None).unwrap();
    //     let chunk_id = chunk_hasher.calc_mix_chunk_id_from_bytes(chunk_data).unwrap();
    //
    //     // 构造PUT请求
    //     let request = http::Request::builder()
    //         .method("PUT")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .header("cyfs-chunk-size", chunk_data.len().to_string())
    //         .body(Full::new(Bytes::from(chunk_data.to_vec())))
    //         .unwrap();
    //
    //     // 发送请求
    //     let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //         .handshake(TokioIo::new(client))
    //         .await
    //         .unwrap();
    //
    //     tokio::spawn(async move {
    //         conn.await.unwrap();
    //     });
    //
    //     let resp = sender.send_request(request).await.unwrap();
    //     // PUT操作应该失败，因为是只读模式
    //     assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // }
    //
    // #[tokio::test]
    // async fn test_get_chunk_status_success() {
    //     // 创建临时目录和配置
    //     let (_temp_dir, mgr_config) = create_test_named_data_mgr();
    //
    //     // 创建服务器
    //     let server = Arc::new(
    //         NdnServer::builder()
    //             .id("test")
    //             .config(mgr_config)
    //             .build()
    //             .await
    //             .unwrap(),
    //     );
    //
    //     let (client, server_stream) = tokio::io::duplex(1024);
    //
    //     // 启动服务器
    //     tokio::spawn(async move {
    //         hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
    //             .await
    //             .unwrap();
    //     });
    //
    //     // 创建一个测试chunk ID
    //     let chunk_data = b"Hello, World! This is test chunk data for NDN server status test.";
    //     let chunk_hasher = ChunkHasher::new(None).unwrap();
    //     let chunk_id = chunk_hasher.calc_mix_chunk_id_from_bytes(chunk_data).unwrap();
    //
    //     // 构造HEAD请求
    //     let request = http::Request::builder()
    //         .method("HEAD")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .body(Full::new(Bytes::new()))
    //         .unwrap();
    //
    //     // 发送请求
    //     let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //         .handshake(TokioIo::new(client))
    //         .await
    //         .unwrap();
    //
    //     tokio::spawn(async move {
    //         conn.await.unwrap();
    //     });
    //
    //     let resp = sender.send_request(request).await.unwrap();
    //     // 状态查询应该成功
    //     assert_eq!(resp.status(), StatusCode::NOT_FOUND); // Chunk不存在，应该返回NOT_FOUND
    // }
    //
    // #[tokio::test]
    // async fn test_get_chunk_success() {
    //     // 创建临时目录和配置
    //     let (_temp_dir, mgr_config) = create_test_named_data_mgr();
    //
    //     // 创建服务器
    //     let server = Arc::new(
    //         NdnServer::builder()
    //             .id("test")
    //             .config(mgr_config)
    //             .build()
    //             .await
    //             .unwrap(),
    //     );
    //
    //     let (client, server_stream) = tokio::io::duplex(1024);
    //
    //     // 启动服务器
    //     tokio::spawn(async move {
    //         hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
    //             .await
    //             .unwrap();
    //     });
    //
    //     // 创建一个测试chunk ID
    //     let chunk_data = b"Hello, World! This is test chunk data for NDN server GET test.";
    //     let chunk_hasher = ChunkHasher::new(None).unwrap();
    //     let chunk_id = chunk_hasher.calc_mix_chunk_id_from_bytes(chunk_data).unwrap();
    //
    //     // 先PUT一个chunk
    //     let put_request = http::Request::builder()
    //         .method("PUT")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .header("cyfs-chunk-size", chunk_data.len().to_string())
    //         .body(Full::new(Bytes::from(chunk_data.to_vec())))
    //         .unwrap();
    //
    //     let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //         .handshake(TokioIo::new(client))
    //         .await
    //         .unwrap();
    //
    //     tokio::spawn(async move {
    //         conn.await.unwrap();
    //     });
    //
    //     let resp = sender.send_request(put_request).await.unwrap();
    //     assert_eq!(resp.status(), StatusCode::OK);
    //
    //     // 再GET这个chunk
    //     let get_request = http::Request::builder()
    //         .method("GET")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .body(Full::new(Bytes::new()))
    //         .unwrap();
    //     //
    //     // let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //     //     .handshake(TokioIo::new(client))
    //     //     .await
    //     //     .unwrap();
    //     //
    //     // tokio::spawn(async move {
    //     //     conn.await.unwrap();
    //     // });
    //
    //     let resp = sender.send_request(get_request).await.unwrap();
    //     // GET操作应该成功
    //     assert_eq!(resp.status(), StatusCode::OK);
    //
    //     let body_bytes = resp.collect().await.unwrap().to_bytes();
    //     assert_eq!(body_bytes.as_ref(), chunk_data);
    // }
    //
    // #[tokio::test]
    // async fn test_get_chunk_not_found() {
    //     // 创建临时目录和配置
    //     let (_temp_dir, mgr_config) = create_test_named_data_mgr();
    //
    //     // 创建服务器
    //     let server = Arc::new(
    //         NdnServer::builder()
    //             .id("test")
    //             .config(mgr_config)
    //             .build()
    //             .await
    //             .unwrap(),
    //     );
    //
    //     let (client, server_stream) = tokio::io::duplex(1024);
    //
    //     // 启动服务器
    //     tokio::spawn(async move {
    //         hyper_serve_http1(Box::new(server_stream), server, StreamInfo::default())
    //             .await
    //             .unwrap();
    //     });
    //
    //     // 创建一个测试chunk ID (但不上传)
    //     let chunk_data = b"Hello, World! This is test chunk data for NDN server GET test.";
    //     let chunk_hasher = ChunkHasher::new(None).unwrap();
    //     let chunk_id = chunk_hasher.calc_mix_chunk_id_from_bytes(chunk_data).unwrap();
    //
    //     // GET不存在的chunk
    //     let request = http::Request::builder()
    //         .method("GET")
    //         .uri(format!("http://localhost/{}", chunk_id.to_base32()))
    //         .body(Full::new(Bytes::new()))
    //         .unwrap();
    //
    //     // 发送请求
    //     let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
    //         .handshake(TokioIo::new(client))
    //         .await
    //         .unwrap();
    //
    //     tokio::spawn(async move {
    //         conn.await.unwrap();
    //     });
    //
    //     let resp = sender.send_request(request).await.unwrap();
    //     // GET操作应该返回NOT_FOUND
    //     assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // }

    #[tokio::test]
    async fn test_factory() {
        let (_temp_dir, mgr_config) = create_test_named_data_mgr();

        let config = NdnServerConfig {
            id: "test".to_string(),
            ty: "ndn".to_string(),
            version: None,
            named_mgr: mgr_config,
        };

        let factory = NdnServerFactory {};
        let result = factory.create(Arc::new(config), None).await;
        assert!(result.is_ok());
    }
}
