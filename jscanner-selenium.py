from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import requests
import time
import re

# User-defined settings
default_username = "user"
default_password = "pw"
default_output = "report.txt"
default_report_404 = "yes"
default_scan_limit = 0
default_nav_links_only = "yes"
default_exclude_terminations = ["/file"]  # URLs ending with these terms will be excluded from 404 reporting
default_exclude_downloads = "yes"  # Exclude links to downloadable files from 404 reporting
default_include_assets = "no"  # Whether to include assets in the scan and report missing assets as 404 errors

class JoomlaSiteScanner:
    def __init__(self, base_url, username, password, report_404=True, scan_limit=0, nav_links_only=False, exclude_terminations=None, exclude_downloads=True, include_assets=False):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.report_404 = report_404
        self.scan_limit = scan_limit
        self.nav_links_only = nav_links_only
        self.exclude_terminations = exclude_terminations if exclude_terminations else []
        self.exclude_downloads = exclude_downloads
        self.include_assets = include_assets
        self.visited_urls = set()
        self.errors = []
        self.stats = {
            "total_pages": 0,
            "total_errors": 0
        }
        self.excluded_urls = set()  # Track URLs excluded from scanning

        # Setup Selenium WebDriver
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service)
        self.wait = WebDriverWait(self.driver, 10)

    def login(self):
        try:
            self.driver.get(self.base_url)
            # Locate login form fields and submit button
            username_field = self.wait.until(EC.presence_of_element_located((By.NAME, "username")))
            password_field = self.driver.find_element(By.NAME, "password")
            login_button = self.driver.find_element(By.XPATH, "//button[@type='submit'] | //input[@type='submit']")

            # Enter credentials and submit the form
            username_field.send_keys(self.username)
            password_field.send_keys(self.password)
            login_button.click()

            # Wait for login to complete by checking for the logout button labelled "Log out"
            self.wait.until(EC.presence_of_element_located((By.XPATH, "//a[text()='Log out'] | //button[text()='Log out']")))
            print("Successfully logged in.")
        except (TimeoutException, NoSuchElementException) as e:
            raise Exception("Login failed. Please check your credentials or the login form parameters.")

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

    def is_asset_link(self, url):
        # Check if the URL points to a typical asset (e.g., images, CSS, JavaScript)
        return re.search(r"\.(png|jpg|jpeg|gif|css|js|svg)$", url, re.IGNORECASE)

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
                print(f"Scanning URL: {url} (referenced by {origin_url})")
            else:
                print(f"Scanning URL: {url}")

            self.driver.get(url)
            soup = BeautifulSoup(self.driver.page_source, "html.parser")
            self.visited_urls.add(url)
            self.stats["total_pages"] += 1

            # Skip reporting 404 errors for assets if include_assets is set to "no"
            if self.report_404:
                response = requests.get(url)
                if response.status_code == 404:
                    if (self.should_exclude_404(url) or
                            (not self.include_assets and self.is_asset_link(url)) or
                            (self.exclude_downloads and self.is_download_link(response))):
                        return
                    self.errors.append((url, response.status_code, origin_url))
                    self.stats["total_errors"] += 1

            self.scan_links(soup, url)
        except requests.RequestException as e:
            self.errors.append((url, str(e), origin_url))
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
            error_entry = {
                "url": error[0],
                "referenced_by": error[2] if error[2] else "N/A"
            }
            error_types[error_code].append(error_entry)

        report += f"--- Errors by Type ---\n"
        for error_code, error_entries in error_types.items():
            report += f"Error {error_code}:\n"
            for entry in error_entries:
                report += f"  - {entry['url']} (referenced by {entry['referenced_by']})\n"

        return report

    def save_report(self, filename="report.txt"):
        with open(filename, "w") as file:
            file.write(self.generate_report())

    def close(self):
        self.driver.quit()

def main():
    base_url = "http://localhost:8082/emsa/extranet"  # Replace with your base URL
    username = default_username
    password = default_password
    output = default_output
    report_404 = default_report_404.lower() == "yes"
    scan_limit = default_scan_limit
    nav_links_only = default_nav_links_only.lower() == "yes"
    exclude_terminations = default_exclude_terminations
    exclude_downloads = default_exclude_downloads.lower() == "yes"
    include_assets = default_include_assets.lower() == "yes"

    scanner = JoomlaSiteScanner(base_url, username, password, report_404=report_404, scan_limit=scan_limit, nav_links_only=nav_links_only, exclude_terminations=exclude_terminations, exclude_downloads=exclude_downloads, include_assets=include_assets)
    try:
        scanner.login()  # Authenticate before scanning
        print("Starting scan...")
        scanner.scan_url(base_url)
        scanner.save_report(output)
        print(f"Scan completed. Report saved to {output}")
    finally:
        scanner.close()

if __name__ == "__main__":
    main()
