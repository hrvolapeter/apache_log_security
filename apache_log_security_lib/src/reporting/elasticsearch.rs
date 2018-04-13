use reporting;
use analyses::Incident;
use elastic::prelude::*;
use error::ReportingErr;
use elastic::client::responses::bulk::BulkErrorsResponse;
use chrono::Utc;
use serde_json;

/// Elasticsearch output
#[derive(Deserialize, Serialize)]
pub struct Elasticsearch {
    /// Elasticsearch address e.g. http://es_host:9200
    pub address: String,
    /// Index name
    pub index: String,
}

#[derive(ElasticType, Serialize, Deserialize)]
pub struct IncidentLog {
    /// Reason of incidet
    pub reason: &'static str,
    /// Text representation of log.
    pub log_msg: String,
    /// Time when incident was reported
    pub timestamp: Date<DefaultDateMapping<ChronoFormat>>,
}

impl reporting::Reporting for Elasticsearch {
    fn report_incidents(&self, incidents: &Vec<Incident>) -> Result<(), ReportingErr> {
        let incidents = incident_to_elastic_incident(incidents);
        let client = self.get_client()?;
        self.put_bulk_incidents(&incidents, &client)
    }
}

impl Elasticsearch {
    fn get_client(&self) -> Result<SyncClient, ReportingErr> {
        Ok(SyncClientBuilder::new()
            .base_url(self.address.clone())
            .build()
            .unwrap())
    }

    fn put_bulk_incidents(
        &self,
        incidents: &Vec<IncidentLog>,
        client: &SyncClient,
    ) -> Result<(), ReportingErr> {
        let req = BulkRequest::for_index(self.index.clone(), self.body(incidents));

        let res = client
            .request(req)
            .send()?
            .into_response::<BulkErrorsResponse>()?;

        if res.is_err() {
            return Err(ReportingErr::Bulk(res.into_iter().collect()));
        }

        Ok(())
    }

    fn body(&self, incidents: &Vec<IncidentLog>) -> String {
        use std::fmt::Write;
        let mut body = String::new();
        for incident in incidents {
            writeln!(
                &mut body,
                r#"{{"index": {{"_index": "{}", "_type": "incident"}}}}"#,
                self.index
            ).unwrap();
            // We can forcfully unwrap since it cant fail
            // Serializer is generates for this type specifically
            writeln!(
                &mut body,
                r#"{}"#,
                serde_json::to_string(&incident).unwrap()
            ).unwrap();
        }

        body
    }
}

fn incident_to_elastic_incident(incidents: &Vec<Incident>) -> Vec<IncidentLog> {
    incidents
        .iter()
        .map(|x| IncidentLog {
            reason: x.reason,
            log_msg: x.log.show(),
            timestamp: Date::new(Utc::now()),
        })
        .collect()
}
