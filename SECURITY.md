# Security

`cloudcostwise` reads your AWS account with your own credentials. It makes AWS
API calls only, refuses any operation that is not a read (`Describe`, `List`,
`Get`, `Search`, `Lookup`), and sends nothing anywhere else.

If you find a way it could write to AWS, leak data off your machine, or run a
command, please email **security@cloudcostwise.io** rather than opening a
public issue. You'll get a reply within three working days.
