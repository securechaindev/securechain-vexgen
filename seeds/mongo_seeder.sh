#!/bin/bash

HAVE_DATA=$(mongosh --username $VULN_DB_USER --password $VULN_DB_PASSWORD --authenticationDatabase admin --host mongo security_db --eval "db.getCollection('vulnerabilities').countDocuments({}) != 0")

if [ $HAVE_DATA == true ]; then
    echo "The database is not empty, no data will be imported"
else
    mongorestore --username $VULN_DB_USER --password $VULN_DB_PASSWORD --authenticationDatabase admin --host mongo --gzip --nsInclude=security_db.* --dir=./seeds/mongo/
    mongorestore --username $VULN_DB_USER --password $VULN_DB_PASSWORD --authenticationDatabase admin --host mongo --gzip --nsInclude=vexgen_db.* --dir=./seeds/mongo/
fi
