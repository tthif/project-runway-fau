#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

project=project-runway-fau
service_name=fau-workroom-counter
service_account="$service_name@$project.iam.gserviceaccount.com"
role=FauWorkroomCounter
role_path="projects/$project/roles/$role"
permissions=datastore.databases.get,datastore.entities.get,datastore.entities.list,datastore.entities.update,datastore.entities.create
wrangler=(npx --yes wrangler@4.168.0)

gcloud auth print-access-token >/dev/null
"${wrangler[@]}" login --device --browser=false

if ! gcloud iam roles describe "$role" --project="$project" >/dev/null 2>&1; then
  gcloud iam roles create "$role" --project="$project" --title="FAU Workroom counter" \
    --description="Read submissions and update the Workroom delivery total" \
    --permissions="$permissions" --stage=GA
fi

if ! gcloud iam service-accounts describe "$service_account" --project="$project" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$service_name" --project="$project" --display-name="FAU Workroom counter"
fi

gcloud projects add-iam-policy-binding "$project" --member="serviceAccount:$service_account" \
  --role="$role_path" --condition=None --quiet >/dev/null

umask 077
credentials_dir=$(mktemp -d)
trap 'rm -f -- "$credentials_dir/key.json" "$credentials_dir/secrets.json"; rmdir -- "$credentials_dir"' EXIT
gcloud iam service-accounts keys create "$credentials_dir/key.json" --project="$project" --iam-account="$service_account"
node - "$credentials_dir/key.json" > "$credentials_dir/secrets.json" <<'NODE'
const fs = require('node:fs');
const key = fs.readFileSync(process.argv[2], 'utf8');
process.stdout.write(JSON.stringify({ FIRESTORE_SERVICE_ACCOUNT: key }));
NODE

"${wrangler[@]}" deploy --secrets-file "$credentials_dir/secrets.json"
