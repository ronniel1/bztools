import argparse
import logging
import netrc
import os
from urllib.parse import urlparse

import bugzilla

BZ_SERVER = "https://bugzilla.redhat.com"
DEFAULT_NETRC_FILE = "~/.netrc"

logging.basicConfig(level=logging.WARN, format="%(levelname)-10s %(message)s")
logger = logging.getLogger(__name__)
logging.getLogger("__main__").setLevel(logging.INFO)


def clonebug(bzclient, bugid, version=None, orig_version_tag=None):
    """Clone this bug similarly as one can do it in the webui"""
    source_bug = bzclient.getbug(bugid)
    new_description = "+++ This bug was initially created "
    new_description += "as a clone of Bug #%s +++\n\n"
    new_description = new_description % (source_bug.id)
    isprivate = False
    isadditional = False
    for rec in source_bug.longdescs:
        if isadditional:
            new_description += "\n--- Additional comment from "
            new_description += rec["creator"]
            new_description += " on "
            new_description += str(rec["time"])
            new_description += "\n\n"
        if "extra_data" in rec.keys():
            new_description += "\n\n*** This bug has been marked "
            new_description += "as a duplicate of bug %s ***\n"
            new_description += new_description % (rec["extra_data"])
        else:
            new_description += rec["text"] + "\n"
        isadditional = True
        if rec["is_private"] == 1:
            isprivate = True
    cc = source_bug.cc
    cc.append(source_bug.reporter)
    depends_on = str(source_bug.bug_id) + " "
    depends_on += " ".join([str(i) for i in source_bug.dependson])
    target_release = version
    if target_release is None:
        target_release = source_bug.target_release
    kwargs = {
        "product": source_bug.product,
        "component": source_bug.component,
        "sub_components": source_bug.sub_components,
        "version": source_bug.version,
        "platform": source_bug.platform,
        "summary": "[{}] {}".format(target_release, source_bug.summary),
        "description": new_description,
        "assigned_to": source_bug.assigned_to,
        "comment_is_private": isprivate,
        "priority": source_bug.priority,
        "bug_severity": source_bug.bug_severity,
        "op_sys": source_bug.op_sys,
        "depends_on": depends_on,
        "blocked": source_bug.blocked,
        "whiteboard": source_bug.whiteboard,
        "keywords": source_bug.keywords,
        "cc": cc,
        "estimated_time": source_bug.estimated_time,
        "remaining_time": source_bug.remaining_time,
        "url": source_bug.bug_file_loc,
        "target_release": target_release,
        "cf_qa_whiteboard": source_bug.qa_whiteboard,
        "cf_clone_of": str(source_bug.id),
        "cf_devel_whiteboard": source_bug.devel_whiteboard,
        "cf_internal_whiteboard": source_bug.internal_whiteboard,
        "cf_build_id": source_bug.cf_build_id,
        "cf_partner": source_bug.cf_partner,
        "cf_verified": ["Any"],
        "cf_environment": source_bug.cf_environment,
        "groups": source_bug.groups,
    }
    for key in kwargs.keys():
        if kwargs[key] is None:
            del kwargs[key]
    newbug = bzclient.createbug(**kwargs)

    # external tracker references
    external_bugs = [
        {
            "ext_bz_bug_url": "https://bugzilla.redhat.com/show_bug.cgi?id={}".format(
                source_bug.id
            )
        }
    ]
    for eb in source_bug.external_bugs:
        neb = {}
        neb["ext_bz_bug_id"] = eb["ext_bz_bug_id"]
        neb["ext_type_id"] = eb["type"]["id"]
        external_bugs.append(neb)

    bzclient._proxy.ExternalBugs.add_external_bug(
        {"bug_ids": [newbug.id], "external_bugs": external_bugs}
    )

    update_dict = {}
    if source_bug.target_release == [target_release]:
        update_dict.update(bzclient.build_update(target_release=['---']))

    if orig_version_tag:
        version_tag = "[{}]".format(orig_version_tag)
        if not source_bug.summary.startswith(version_tag):
            update_dict.update(bzclient.build_update(
                summary="{} {}".format(version_tag, source_bug.summary)
            ))

    if len(update_dict) > 0:
        bzclient.update_bugs([source_bug.id], update_dict)

    return newbug


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
    return username, password


def get_credentials_from_netrc(server, netrc_file=DEFAULT_NETRC_FILE):
    cred = netrc.netrc(os.path.expanduser(netrc_file))
    username, _, password = cred.authenticators(server)
    return username, password


def run():
    parser = argparse.ArgumentParser(
        description="Clone BZ bug and mark the new bug for 4.8.0"
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
    parser.add_argument("-i", "--bz-id", required=True, help="BZ ID to clone")
    args = parser.parse_args()

    busername, bpassword = get_login(args.bugzilla_user_password, BZ_SERVER, args.netrc)
    bzclient = get_bz_client(busername, bpassword)

    n = clonebug(bzclient, args.bz_id, version="4.8.0", orig_version_tag="master")
    print(n.id)


if __name__ == "__main__":
    run()
