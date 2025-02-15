
# Initialize management interfaces - Primary
curl -X POST -H "content-type: application/json" "https://$PRIMARY_PARTICIPANT_HOST/mgmt/init" \
    -d "{\"partner\":\"https://$PARTNER_PARTICIPANT_HOST\",\"psk\":\"$PARTICIPANT_PSK\"}"

# Initialize management interfaces - Partner
curl -X POST -H "content-type: application/json" "https://$PARTNER_PARTICIPANT_HOST/mgmt/init" \
    -d "{\"partner\":\"https://$PRIMARY_PARTICIPANT_HOST\",\"psk\":\"$PARTICIPANT_PSK\"}"



