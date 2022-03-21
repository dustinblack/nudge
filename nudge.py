"""
Copyright 2021 Joe Talerico

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import smtplib
import logger as log
from textwrap3 import wrap
import jira
import os
import argparse
import operator
import re
import webbrowser
import sys
from datetime import datetime, timedelta

parser= argparse.ArgumentParser(description="Tool to query and help nudge JIRA users")
parser.add_argument(
    "--report",
    default=False,
    action='store_true',
    dest="report")
parser.add_argument(
    "--dash",
    default=False,
    action='store_true',
    dest="dash")
args = parser.parse_args()

dashFile = '/var/tmp/nudge.html'

# Team Name
teamName="Team"

# JIRA Connection Setup
server=os.environ['JIRA_Server']
username=os.environ['JIRA_User']
password=os.environ['JIRA_Pass']
token=os.environ['JIRA_Token']

# Queries, double-space delimited
queries=os.environ['JIRA_Queries'].split('  ')

# EMAIL Nudges
sendEmail=False

if sendEmail :
    smtpServer=os.environ['EMAIL_Server']
    smtpFrom=os.environ['EMAIL_From']
    smtpTo=os.environ['EMAIL_To']

options = { 'server': server }
if token :
    conn = jira.JIRA(options, token_auth=(token))
else :
    conn = jira.JIRA(options, basic_auth=(username, password))

issues=[]
nudges=[]
nudgeMessage=[]

## TODO I might need this to looup the custom field name in a better way
#allfields = conn.fields()
#nameMap = {field['name']:field['id'] for field in allfields}
#for field in allfields:
#    print(field)

if len(queries) < 1:
    log.logger.error("No JIRA queries provided.")
    exit(1)

for query in queries:
    if query == "":
        continue
    log.logger.info("Running query: %s" % (query))
    issues.append(conn.search_issues(jql_str=query,json_result=True,maxResults=200))

if len(issues) > 0 :
    for issue in issues:
        for jira in issue['issues'] :
            if jira['fields']['assignee'] is None:
                owner = "No Owner"
            else :
                owner = jira['fields']['assignee']['displayName']

            ## TODO Mr. Ugly Code needs cleanup
            for sprint in jira['fields']['customfield_12310940'] :
                res = re.sub(r'^.*?\[', '[', sprint)
                lst = res.strip('][').split(',')
                foo = {}
                for l in lst :
                    foo[l.split('=')[0]] = l.split('=')[1]
                if "ACTIVE" in foo['state'] :
                    sprint = foo['name']

            nudges.append({
                "JIRA" : "{}".format(jira['key']),
                "OWNER" : "{}".format(owner),
                "SPRINT" : "{}".format(sprint),
                "CREATOR" : "{}".format(jira['fields']['creator']['displayName']),
                "STATUS" : "{}".format(jira['fields']['status']['name']),
                "LINK" : "{}/browse/{}".format(server,jira['key']),
                "UPDATED" : "{}".format(jira['fields']['updated']),
                "DESC" : "{}".format(jira['fields']['description']),
                "LABELS" : "{}".format(jira['fields']['labels']),
                "SUMM" : "{}".format(jira['fields']['summary']),
                "ID" : "{}".format(jira['id']),
                "COMMENTS" : conn.comments(jira['key']),
                "TASKS" : jira['fields']['subtasks']
            })

nudges.sort(key=operator.itemgetter('SPRINT'))

if args.report or args.dash :
    if args.dash :
        sys.stdout = open(dashFile, 'w')

    nudges.sort(key=operator.itemgetter('SPRINT'))
    currentSprint = ''
    if args.dash:
        print("<html><body><pre>")
    for nudge in nudges:
        if currentSprint != nudge['SPRINT'] :
            currentSprint = nudge['SPRINT']
            print("+{}+".format("="*100))
            if args.report: print("\x1b[1;37;44m")
            print("\n=== SPRINT: {} ===".format(currentSprint))
            if args.report: print("\x1b[0m")
        if len(nudge['COMMENTS']) > 0 :
            latestCommentID = nudge['COMMENTS'].pop()
            latestComment = conn.comment(nudge['ID'],latestCommentID).body
        else:
            latestComment = "No comments"
        if nudge['STATUS'] == "To Do":
            continue

        epic = conn.search_issues("project = PerfScale AND id={} AND \"Epic Link\" is not EMPTY".format(nudge['ID']))

        #if args.dash:
        #    print("<tr><td>")

        print("+{}+".format("="*100))
        if len(epic) == 0 :
            if args.report: print("\x1b[0;30;43m")
            print("\n -- NOTE:: {} has no EPIC assigned, please link to an EPIC -- ".format(nudge['JIRA']))
            if args.report: print("\x1b[0m")
        updated = datetime.strptime(nudge['UPDATED'].split('T')[0], '%Y-%m-%d')
        if (datetime.now() - updated) > timedelta(days = 5):
            if args.report: print("\x1b[1;37;41m")
            print("\n -- NOTE:: Has not been updated since {}. Please {} provide an update. -- ".format(nudge['UPDATED'].split('T')[0], nudge['OWNER']))
            if args.report: print("\x1b[0m")
        print("{} - {} \nLabels: {}\nOwner: {}\nCreator: {}\nStatus: {}\nLink: {}\nUpdated: {}\nLast Comment:\n{}\n\n".
              format(nudge['JIRA'],
                     nudge['SUMM'],
                     nudge['LABELS'],
                     nudge['OWNER'],
                     nudge['CREATOR'],
                     nudge['STATUS'],
                     nudge['LINK'],
                     nudge['UPDATED'].split('T')[0],
                     "\n".join(wrap(latestComment,100))
             ))
        if len(nudge['TASKS']) > 0 :
            print("Sub-Tasks for {}".format(nudge['JIRA']))
            for tasks in nudge['TASKS'] :
                print("JIRA : {}\nStatus : {}\nSummary :{}\n".format(tasks['key'],tasks['fields']['status']['name'],tasks['fields']['summary']))

        #if args.dash:
        #    print("</td></tr>")

    print("+{}+".format("="*100))
    if args.dash:
        print("</pre></body></html>")
        sys.stdout.close()
        webbrowser.open('file://{}'.format(dashFile), new=2)

else :
    log.logger.info("Number of nudges: {}".format(len(nudges)))

    if len(nudges) > 0 :
        for nudge in nudges:
            nudgeMessage.append("{}\nHas not been updated since {}. Please {} provide an update {}\n".
                    format(nudge['JIRA'],
                        nudge['UPDATED'].split('T')[0],
                        nudge['OWNER'],
                        nudge['LINK']))

        if sendEmail :
    	    server = smtplib.SMTP(smtpServer)
    	    msg = "Subject: {} JIRA Nudge\n\n".format(teamName)
    	    msg += "Hello PerfScale Team,\nBelow are the current nudges, please address them today.\n\n"
    	    msg += "{}".format("\n".join(nudgeMessage))
    	    server.sendmail(smtpFrom, smtpTo, msg)
    	    server.quit()
    	    log.logger.info("Email Sent")
        else :
            for nudge in nudges:
                print("{} Needs to be updated by {}. Last update was {}. Link {}".
                    format(nudge['JIRA'],
                            nudge['OWNER'],
                            nudge['UPDATED'],
                            nudge['LINK']))
