use std::io;
use std;
use elastic;
use elastic::client::responses::bulk::ErrorItem;
use lettre::sendmail;

#[derive(Debug)]
pub enum LibErr {
    ReportingErr(ReportingErr),
    InputErr(InputErr),
}

impl std::convert::From<InputErr> for LibErr {
    fn from(err: InputErr) -> LibErr {
        LibErr::InputErr(err)
    }
}

impl std::convert::From<ReportingErr> for LibErr {
    fn from(err: ReportingErr) -> LibErr {
        LibErr::ReportingErr(err)
    }
}

#[derive(Debug)]
pub enum ReportingErr {
    Elastic(elastic::Error),
    Bulk(Vec<ErrorItem>),
    Email(sendmail::error::Error),
}

impl std::convert::From<elastic::Error> for ReportingErr {
    fn from(err: elastic::Error) -> ReportingErr {
        ReportingErr::Elastic(err)
    }
}

impl std::convert::From<sendmail::error::Error> for ReportingErr {
    fn from(err: sendmail::error::Error) -> ReportingErr {
        ReportingErr::Email(err)
    }
}

#[derive(Debug)]
pub enum InputErr {
    Io(io::Error),
    Elastic(elastic::Error),
    NoDocuments(),
}

impl std::convert::From<io::Error> for InputErr {
    fn from(err: io::Error) -> InputErr {
        InputErr::Io(err)
    }
}

impl std::convert::From<elastic::Error> for InputErr {
    fn from(err: elastic::Error) -> InputErr {
        InputErr::Elastic(err)
    }
}
