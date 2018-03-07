use elastic::prelude::*;
use input;
use analyses;
use analyses::access_logs::AccessLog;
use chrono::prelude::*;
use error::InputErr;

/// Input source type
#[derive(Deserialize, Serialize)]
pub struct Elasticsearch {
    /// Elasticsearch address e.g. http://es_host:9200
    pub address: String,
    /// Index name
    pub index: String,
}

/// Struct for representing elasticsearch log
///
/// Access log must conform to this structure
#[derive(Serialize, Deserialize, ElasticType)]
struct ElasticsearchLog {
    pub response_code: i32,
    pub client: String,
    pub path: String,
    pub date_time: DateTime<Utc>,
    pub size_returned: i32,
}

/// Struct for logging last run
#[derive(Serialize, Deserialize, ElasticType, PartialEq)]
struct RunLog {
    pub id: i32,
    pub date_time: DateTime<Utc>,
    pub state: String,
}

impl input::Input for Elasticsearch {
    fn get_logs(&self) -> Result<Vec<Box<analyses::Analysable>>, InputErr> {
        let client = self.get_client()?;

        let last_run = Self::last_run(&client).unwrap_or(RunLog {
            id: 0,
            date_time: Utc.timestamp(0, 0),
            state: "Done".to_string(),
        });

        let response = client
            .search::<ElasticsearchLog>()
            .index(self.index.clone())
            .body(json!({
                "query": {
                    "range": {
                        "date_time": {
                            "gte": last_run.date_time.timestamp(),
                            "format": "epoch_second",
                        },
                    },
                },
                "sort": {"date_time": "desc"},
                "size": 1000,
            }))
            .send()?;

        let result = Self::map_access_log(&response.documents().collect());
        Self::update_last_run(
            &client,
            &RunLog {
                id: last_run.id + 1,
                date_time: Utc::now(),
                state: "Done".to_string(),
            },
        )?;
        Ok(result)
    }
}

impl Elasticsearch {
    fn get_client(&self) -> Result<SyncClient, InputErr> {
        Ok(SyncClientBuilder::new()
            .base_url(self.address.clone())
            .build()?)
    }

    fn map_access_log(hits: &Vec<&ElasticsearchLog>) -> Vec<Box<analyses::Analysable>> {
        hits.iter()
            .map(|ref log| {
                Box::new(AccessLog::new(
                    log.response_code as u32,
                    log.client.clone(),
                    log.path.clone(),
                    Utc::now(),
                    log.size_returned as u32,
                )) as Box<analyses::Analysable>
            })
            .collect()
    }

    fn last_run(client: &SyncClient) -> Result<RunLog, InputErr> {
        let result = client
            .search::<RunLog>()
            .index(".log-security")
            .body(json!({"sort": {"date_time": "desc"}}))
            .send()?;
        result
            .into_documents()
            .next()
            .ok_or(InputErr::NoDocuments())
    }

    fn update_last_run(client: &SyncClient, log: &RunLog) -> Result<(), InputErr> {
        client
            .document_index(index(".log-security"), id(log.id), log)
            .send()?;
        Ok(())
    }
}
