import argparse
import logging
import netrc
import os
import re
import subprocess
from urllib.parse import urlparse

import bugzilla
import jira

JIRA_SERVER = "https://issues.redhat.com/"
BZ_SERVER = "https://bugzilla.redhat.com"
AUTO_VERIFIED_LABEL = "e2e-auto-verified"
DEFAULT_NETRC_FILE = "~/.netrc"
REPO_URL_TEMPLATE = "https://github.com/openshift/{}"
JIRA_ISSUE_REGEX = re.compile(r"(OCPBUGSM-[0-9]+)")
BZ_ISSUE_REGEX = re.compile(r"(BZ|Bug)[- ]([0-9]+)")
VALID_REPOS = ["assisted-installer", "assisted-service", "assisted-installer-agent"]
BZ_REFERENCE_FIELD = "customfield_12316840"

logging.basicConfig(level=logging.INFO, format="%(levelname)-10s %(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)


def bz_url_query(bzclient, urlquery):
    """Search for on-qa bugs that should be flipped to verified"""
    logger.info("Searching for bugs matching query %s", urlquery)
    query = bzclient.url_to_query(urlquery)
    query["include_fields"] = ["id", "summary", "status"]
    bugs = bzclient.query(query)
    return bugs


def get_jira_client(username, password):
    logger.info("log-in to Jira with username: %s", username)
    return jira.JIRA(JIRA_SERVER, basic_auth=(username, password))


def get_bz_client(username, password):
    logger.info("log-in to bugzilla with username: %s", username)
    if username == "apikey":
        return bugzilla.RHBugzilla3(BZ_SERVER, api_key=password)

    return bugzilla.RHBugzilla3(BZ_SERVER, user=username, password=password)


def get_login(user_password, server, netrc_path=None):
    if user_password is None:
        username, password = get_credentials_from_netrc(
            urlparse(server).hostname, netrc_path
        )
    else:
        try:
            [username, password] = user_password.split(":", 1)
        except Exception:
            logger.error("Failed to parse user:password")
            return
    return username, password


def get_credentials_from_netrc(server, netrc_file=DEFAULT_NETRC_FILE):
    cred = netrc.netrc(os.path.expanduser(netrc_file))
    username, _, password = cred.authenticators(server)
    return username, password


def create_dir(dirname):
    try:
        os.mkdir(dirname)
    except Exception:
        pass


def clone_repo(repo):
    dirname = "temp/{}".format(os.path.basename(repo))
    if os.path.isdir(dirname):
        subprocess.check_call("git fetch -tf", shell=True, cwd=dirname)
    else:
        repo_url = REPO_URL_TEMPLATE.format(repo)
        subprocess.check_call("git clone {}".format(repo_url), shell=True, cwd="temp")
    return dirname


def get_relative_commit(relative_date, repo_dir):
    raw_log = subprocess.check_output(
        "git log --since={} --pretty=format:'%H'| tail -n1".format(relative_date),
        shell=True,
        cwd=repo_dir,
    )
    return raw_log.decode("utf-8")


def get_issues_list_for_repo(repos, to_commits, relative_date):
    repos_commits = dict(zip(repos, to_commits))
    matches = {"jira_issues": [], "bz_issues": []}
    for repo, to_commit in repos_commits.items():
        logger.info("Processing repo %s and to commit %s", repo, to_commit)
        create_dir("temp")
        dirname = clone_repo(repo)
        from_commit = get_relative_commit(relative_date, dirname)
        raw_log = subprocess.check_output(
            "git log --pretty=medium {}...{} ".format(from_commit, to_commit),
            shell=True,
            cwd=dirname,
        )
        jira_matches = JIRA_ISSUE_REGEX.findall(raw_log.decode("utf-8"), re.MULTILINE)
        bz_matches = BZ_ISSUE_REGEX.findall(raw_log.decode("utf-8"), re.MULTILINE)
        matches["jira_issues"].extend(jira_matches)
        matches["bz_issues"].extend([x[1] for x in bz_matches])
    return matches


def get_jira_issues_info(jclient, keys):
    issues = jclient.search_issues(
        "issue in ({})".format(",".join(keys)),
        fields=[
            "key",
            "summary",
            "status",
            "assignee",
            BZ_REFERENCE_FIELD,
            "fixVersions",
        ],
    )
    return issues


def get_bugs_to_change(jira_issues, repo_bz_bugs):
    """Identify BZ bugs to change status"""
    for issue in jira_issues:
        bz_id = issue.raw["fields"][BZ_REFERENCE_FIELD]["bugid"]
        repo_bz_bugs.append(str(bz_id))
    logger.info(
        "The following bugs will be changed if BZ criteria matches: %s", repo_bz_bugs
    )
    return repo_bz_bugs


def get_qa_whiteboard_label(qa_whiteboard):
    """Append qa whiteboard label to bz"""
    if re.search(AUTO_VERIFIED_LABEL, qa_whiteboard):
        return qa_whiteboard
    else:
        return qa_whiteboard + " " + AUTO_VERIFIED_LABEL


def update_bz_status(
    bzclient, bz_ids, initial_status, update_status, dry_run, summary_regex
):
    """Change BZ status based on initial status and a partial summary match."""
    updated_bugs = []
    for bz_id in list(dict.fromkeys(bz_ids)):
        bug = bzclient.getbug(bz_id)
        if bug.status == initial_status and re.search(summary_regex, bug.summary):
            updated_bugs.append(
                "{} - [{}] - {}".format(bug.id, bug.status, bug.summary)
            )
            logger.info(
                "Updating bz id %s status from %s to %s. BZ Summary: %s",
                bug.id,
                bug.status,
                update_status,
                bug.summary,
            )
            new_qa_whiteboard = get_qa_whiteboard_label(bug.cf_qa_whiteboard)
            logger.info(
                "Updating qa white board to %s for %s", new_qa_whiteboard, bug.id
            )
            if not dry_run:
                update = bzclient.build_update(
                    status=update_status, qa_whiteboard=new_qa_whiteboard
                )
                bzclient.update_bugs([bug.id], update)
            else:
                logger.info("Dry run set - bug %s not changed", bug.id)
        else:
            if bug.status != initial_status:
                logger.info(
                    "Not updating bug %s - Current status %s does not match expected start status %s",
                    bug.id,
                    bug.status,
                    initial_status,
                )
            if not re.search(summary_regex, bug.summary):
                logger.info(
                    "Not updating bug %s - Summary regex %s is not matched in the bug summary %s",
                    bug.id,
                    summary_regex,
                    bug.summary,
                )
    return updated_bugs


def run():
    parser = argparse.ArgumentParser(
        description="Identify BZs that should have status set to verified"
    )
    loginGroup = parser.add_argument_group(title="login options")
    loginArgs = loginGroup.add_mutually_exclusive_group()
    loginArgs.add_argument(
        "--netrc", default="~/.netrc", required=False, help="netrc file"
    )
    loginArgs.add_argument(
        "-bup",
        "--bugzilla-user-password",
        required=False,
        help="Bugzilla username and password in the format of user:pass",
    )
    loginArgs.add_argument(
        "-jup",
        "--jira-user-password",
        required=False,
        help="Jira username and password in the format of user:pass",
    )
    parser.add_argument(
        "-r",
        "--repos",
        choices=VALID_REPOS,
        nargs="+",
        help="Get tickets for the specified repo",
    )
    parser.add_argument(
        "-t",
        "--to-commits",
        help="Space separated to git commit revision match each --repos chosen",
        nargs="+",
        required=True,
    )
    parser.add_argument(
        "-f",
        "--from-relative-date",
        help="From commit relative to To commit. Accepts any value of --since in 'git log --since=2.weeks'",
        type=str,
        required=False,
        default="2.weeks",
    )
    parser.add_argument(
        "-d", "--dry-run", action="store_true", help="Dry run - do not update Bugzilla"
    )
    parser.add_argument(
        "-i",
        "--initial-status",
        default="ON_QA",
        help="status that bug should be set to initially - ex: ON_QA",
    )
    parser.add_argument(
        "-c",
        "--change-status",
        default="VERIFIED",
        help="status bug will be updated to - ex: VERIFIED",
    )
    parser.add_argument(
        "-s",
        "--summary-regex",
        default=r"^\[master\]",
        help="regex to match in BZ summary to perform status update",
    )
    parser.add_argument(
        "-b",
        "--bz-override",
        nargs="+",
        required=False,
        help="overrides bugs to have status changed - Ex: 1971755 1972696 1972697",
    )

    args = parser.parse_args()

    jusername, jpassword = get_login(args.jira_user_password, JIRA_SERVER, args.netrc)
    busername, bpassword = get_login(args.bugzilla_user_password, BZ_SERVER, args.netrc)
    bzclient = get_bz_client(busername, bpassword)
    jclient = get_jira_client(jusername, jpassword)

    issues_in_repos = get_issues_list_for_repo(
        args.repos, args.to_commits, args.from_relative_date
    )

    if (
        len(issues_in_repos["jira_issues"]) == 0
        and len(issues_in_repos["bz_issues"]) == 0
    ):
        logger.info("No BZ bugs identified for updating")
        return

    jira_issues = get_jira_issues_info(jclient, issues_in_repos["jira_issues"])
    if len(jira_issues) == 0:
        logger.info("No BZ bugs identified from Jira issues")
        return

    logger.info("Jira and BZ issues identified in repo capture: %s", issues_in_repos)
    logger.info("Jira and mapped BZ issues from Jira capture: %s", jira_issues)

    bugs_to_change = get_bugs_to_change(jira_issues, issues_in_repos["bz_issues"])

    if args.bz_override:
        bugs_to_change = args.bz_override
        logger.info(
            "Bug override is set - The following bugs will have status changed: %s",
            bugs_to_change,
        )

    updated_bugs = update_bz_status(
        bzclient,
        bugs_to_change,
        args.initial_status,
        args.change_status,
        args.dry_run,
        args.summary_regex,
    )

    logger.info("Updated bugs: %s", updated_bugs)


if __name__ == "__main__":
    run()
