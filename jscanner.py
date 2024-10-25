import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
import re

# User-defined settings
default_username = "username"
default_password = "password"
default_output = "report.txt"
default_report_404 = "yes"
default_scan_limit = 0
default_nav_links_only = "no"
default_exclude_terminations = ["/file"]  # URLs ending with these terms will be excluded from 404 reporting
default_exclude_downloads = "yes"  # Exclude links to downloadable files from 404 reporting

class JoomlaSiteScanner:
    def __init__(self, base_url, username, password, report_404=True, scan_limit=0, nav_links_only=False, exclude_terminations=None, exclude_downloads=True):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.report_404 = report_404
        self.scan_limit = scan_limit
        self.nav_links_only = nav_links_only
        self.exclude_terminations = exclude_terminations if exclude_terminations else []
        self.exclude_downloads = exclude_downloads
        self.session = requests.Session()
        self.visited_urls = set()
        self.errors = []
        self.stats = {
            "total_pages": 0,
            "total_errors": 0
        }
        self.excluded_urls = set()  # Track URLs excluded from scanning

    def login(self):
        # Get the homepage to retrieve CSRF tokens or hidden fields
        response = self.session.get(self.base_url)

        if response.status_code != 200:
            raise Exception("Failed to load homepage for login.")

        soup = BeautifulSoup(response.content, 'html.parser')

        # Try to find the login form by common characteristics
        login_form = None
        forms = soup.find_all('form')

        for form in forms:
            # Check if the form has fields that look like a login form
            form_inputs = form.find_all("input")
            has_username = any(input.get("name") in ["username", "user", "jform[username]"] for input in form_inputs)
            has_password = any(input.get("name") in ["password", "pass", "jform[password]"] for input in form_inputs)

            if has_username and has_password:
                login_form = form
                break

        if not login_form:
            raise Exception("Login form not found on homepage. Please check the homepage structure.")

        # Prepare the payload for login
        payload = {
            "username": self.username,
            "password": self.password,
        }

        # Extract hidden fields (including CSRF tokens)
        for hidden_input in login_form.find_all("input", type="hidden"):
            if hidden_input.get("name") and hidden_input.get("value"):
                payload[hidden_input["name"]] = hidden_input["value"]

        # Find the action URL for the login form
        login_action = login_form.get("action")
        if not login_action:
            raise Exception("Login form action URL not found.")

        login_url = urljoin(self.base_url, login_action)

        # Submit the login form with the payload
        try:
            response = self.session.post(login_url, data=payload)
            if response.status_code == 200 and ('Logout' in response.text or 'logout' in response.text):
                print("Successfully logged in.")
            else:
                raise Exception("Login failed. Please check your credentials or the login form parameters.")
        except requests.RequestException as e:
            raise Exception(f"Login request failed: {str(e)}")

    def is_valid_url(self, url):
        parsed = urlparse(url)
        # Ensure the URL is part of the base site, has no fragment, and does not include query parameters
        return (bool(parsed.netloc) and bool(parsed.scheme) and not parsed.fragment and
                parsed.netloc == urlparse(self.base_url).netloc)

    def should_exclude_404(self, url):
        # Check if the URL should be excluded from 404 reporting based on termination
        for termination in self.exclude_terminations:
            if url.endswith(termination):
                return True
        return False

    def is_download_link(self, response):
        # Check if the response indicates a downloadable file
        content_disposition = response.headers.get('Content-Disposition', '').lower()
        if "attachment" in content_disposition:
            return True
        # Additionally check common file extensions in the URL
        if re.search(r"\.(zip|pdf|docx?|xlsx?|pptx?|rar|tar\.gz|7z)$", response.url, re.IGNORECASE):
            return True
        return False

    def scan_url(self, url, origin_url=None):
        if url in self.visited_urls or not self.is_valid_url(url):
            return

        if self.scan_limit > 0 and self.stats["total_pages"] >= self.scan_limit:
            print("Scan limit reached. Stopping further scans.")
            return

        if any(url.endswith(termination) for termination in self.exclude_terminations):
            print(f"Excluding URL from further scans: {url}")
            self.excluded_urls.add(url)
            return

        try:
            if origin_url:
                print(f"Scanning URL: {url} (discovered from {origin_url})")
            else:
                print(f"Scanning URL: {url}")
            response = self.session.get(url, timeout=10)
            self.visited_urls.add(url)
            self.stats["total_pages"] += 1

            if response.status_code != 200:
                if response.status_code == 404 and (not self.report_404 or self.should_exclude_404(url)):
                    return
                if response.status_code == 404 and self.exclude_downloads and self.is_download_link(response):
                    return
                self.errors.append((url, response.status_code))
                self.stats["total_errors"] += 1

            soup = BeautifulSoup(response.content, "html.parser")
            self.scan_links(soup, url)
        except requests.RequestException as e:
            self.errors.append((url, str(e)))
            self.stats["total_errors"] += 1

    def scan_links(self, soup, base_url):
        # Only scan links that are clean, human-readable, and visible on the page
        for link in soup.find_all("a", href=True):
            href = link.get("href")

            # Filter out links that are not suitable for a human user to follow
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                # Ensure the link is part of the current website and follows a simple, readable structure
                full_url = urljoin(base_url, href)
                parsed_full_url = urlparse(full_url)

                # Skip scanning links derived from excluded URLs
                if any(excluded_url in base_url for excluded_url in self.excluded_urls):
                    print(f"Skipping derived URL from excluded source: {full_url}")
                    continue

                # Only follow links that do not have query parameters or extra path components that look dynamic/user-specific
                if (self.is_valid_url(full_url) and
                        not re.search(r"[?=&]", parsed_full_url.query) and
                        not any(part.isdigit() for part in parsed_full_url.path.split('/'))):
                    self.scan_url(full_url, origin_url=base_url)

    def generate_report(self):
        report = f"--- Joomla Site Scan Report ---\n"
        report += f"Base URL: {self.base_url}\n"
        report += f"Total Pages Scanned: {self.stats['total_pages']}\n"
        report += f"Total Errors Found: {self.stats['total_errors']}\n\n"

        error_types = {}
        for error in self.errors:
            error_code = error[1]
            if error_code not in error_types:
                error_types[error_code] = []
            error_types[error_code].append(error[0])

        report += f"--- Errors by Type ---\n"
        for error_code, urls in error_types.items():
            report += f"Error {error_code}:\n"
            for url in urls:
                report += f"  - {url}\n"

        return report

    def save_report(self, filename="report.txt"):
        with open(filename, "w") as file:
            file.write(self.generate_report())

def main():
    parser = argparse.ArgumentParser(description="Simple Joomla Site Scanner with Authentication")
    parser.add_argument("base_url", help="Base URL of the Joomla site to scan (e.g., http://localhost/joomla/)")
    parser.add_argument("--username", help="Username for Joomla login", default=default_username)
    parser.add_argument("--password", help="Password for Joomla login", default=default_password)
    parser.add_argument("--output", help="Output file for the report", default=default_output)
    parser.add_argument("--report-404", help="Whether to report 404 errors (yes/no)", default=default_report_404)
    parser.add_argument("--scan-limit", help="Limit the number of URLs to scan (0 for no limit)", type=int, default=default_scan_limit)
    parser.add_argument("--nav-links-only", help="Whether to scan only navigational links (yes/no)", default=default_nav_links_only)
    parser.add_argument("--exclude-terminations", help="Comma-separated list of URL terminations to exclude from 404 reporting", default=','.join(default_exclude_terminations))
    parser.add_argument("--exclude-downloads", help="Whether to exclude downloadable files from 404 reporting (yes/no)", default=default_exclude_downloads)
    args = parser.parse_args()

    report_404 = args.report_404.lower() == "yes"
    nav_links_only = args.nav_links_only.lower() == "yes"
    exclude_terminations = [term.strip() for term in args.exclude_terminations.split(',')]
    exclude_downloads = args.exclude_downloads.lower() == "yes"

    scanner = JoomlaSiteScanner(args.base_url, args.username, args.password, report_404=report_404, scan_limit=args.scan_limit, nav_links_only=nav_links_only, exclude_terminations=exclude_terminations, exclude_downloads=exclude_downloads)
    scanner.login()  # Authenticate before scanning
    print("Starting scan...")
    scanner.scan_url(args.base_url)
    scanner.save_report(args.output)

    print(f"Scan completed. Report saved to {args.output}")

if __name__ == "__main__":
    main()
