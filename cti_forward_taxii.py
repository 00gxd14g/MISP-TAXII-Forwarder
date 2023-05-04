"""
CTI Extractor for MISP and forwarding STIX file in TAXII server.
"""
import datetime
import time
from pymisp import PyMISP
from stix.core import STIXPackage
from stix.indicator import Indicator
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cabby import create_client


def log(message):
    """Log messages with timestamp."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("result.log", "a", encoding='utf-8') as log_file:
        log_file.write(f"{now} {message}\n")
    print(f"{now} {message}")


def get_misp_events(misp, tag_to_search, last_processed_event_id):
    """Get MISP events by tag and filtered by last_processed_event_id."""
    events = misp.search(
        controller='events',
        tags=tag_to_search,
        to_ids=True,
        last=None,
        enforceWarninglist=True
    )
    return [event for event in events if int(event['Event']['id']) < last_processed_event_id]


class CustomDomainName(DomainName):
    """Custom Domain Name class."""

    def __init__(self, value=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if value is not None:
            self.value = value


def process_events(events):
    """Process MISP events and convert them into STIX packages."""
    stix_package = STIXPackage()

    for event in events:
        for attribute in event['Event']['Attribute']:
            indicator = Indicator()

            if attribute['type'] == "ip-dst" or attribute['type'] == "ip-src":
                address = Address(address_value=attribute['value'], category=Address.CAT_IPV4)
                indicator.add_observable(address)
            elif attribute['type'] == "domain":
                domain = CustomDomainName(value=attribute['value'])
                indicator.add_observable(domain)
            elif attribute['type'] == "url":
                url = URI(value=attribute['value'], type_=URI.TYPE_URL)
                indicator.add_observable(url)
            elif attribute['type'] == "md5":
                file_object = File()
                file_object.md5 = attribute['value']
                indicator.add_observable(file_object)

            stix_package.add_indicator(indicator)

    return stix_package


def save_stix_package_to_file(stix_package, filepath):
    """Save STIX package to a file."""
    with open(filepath, "w", encoding='utf-8') as file:
        file.write(stix_package.to_xml(encoding='utf-8').decode('utf-8'))


def push_stix_package_to_taxii(filepath):
    """Push STIX package to TAXII server."""
    # TAXII server configuration
    taxii_url = ""
    taxii_discovery_path = ""
    taxii_inbox_path = ""
    taxii_username = ""
    taxii_password = ""

    # Create a TAXII client
    client = create_client(
        discovery_path=taxii_url + taxii_discovery_path,
        use_https=False,
    )
    client.set_auth(username=taxii_username, password=taxii_password)

    # Push the STIX package to the TAXII server
    with open(filepath, "r", encoding='utf-8') as file:
        stix_package_str = file.read()
response = client.push(
        content=stix_package_str,
        content_binding="urn:stix.mitre.org:xml:1.1.1",
        collection_names=[''],
        uri=taxii_url + taxii_inbox_path
    )

    return response


def main():
    """Main function."""
    # Replace with your MISP API key and URL
    misp_api_key = ""
    misp_url = ""
    tag_to_search = ""
    stix_output_path = "stix_package.xml"

    misp = PyMISP(misp_url, misp_api_key, False)

    while True:
        # Get the processed_event_ids
        try:
            with open("processed_events_ids.txt", "r", encoding='utf-8') as file:
                processed_event_ids = set(map(int, file.read().splitlines()))
        except FileNotFoundError:
            processed_event_ids = set()
            with open("processed_events_ids.txt", "w", encoding='utf-8') as file:
                pass

        last_processed_event_id = max(processed_event_ids) if processed_event_ids else 0
        events = get_misp_events(misp, tag_to_search, last_processed_event_id)

        new_events = [event for event in events if int(event['Event']['id']) not in processed_event_ids]

        if not new_events:
            log("No new events to process.")
            time.sleep(1800)  # Wait for an hour before checking for new events again
        else:
            log(f"Processing {len(new_events)} new events...")

            stix_package = process_events(new_events)

            if not stix_package.indicators:
                log("No attributes to convert to STIX indicators.")
            else:
                log(f"Converted {len(stix_package.indicators)} attributes to STIX indicators.")
                save_stix_package_to_file(stix_package, stix_output_path)
                try:
                    response = push_stix_package_to_taxii(stix_output_path)
                    if response.status == 200:
                        log("STIX package successfully pushed to the TAXII server.")
                    else:
                        log(f"Failed to push STIX package to the TAXII server. Status code: {response.status}")
                except Exception as error:
                    log(f"Error while pushing STIX package to TAXII server: {str(error)}")

            # Update the processed_event_ids
            for event in new_events:
                processed_event_ids.add(int(event['Event']['id']))

            # Save the processed_event_ids
            with open("processed_events_ids.txt", "w", encoding='utf-8') as file:
                for event_id in processed_event_ids:
                    file.write(str(event_id) + "\n")

            # Wait for a short period (e.g., 10 seconds) before checking for new events again
            time.sleep(1800)


if __name__ == "__main__":
    main()
