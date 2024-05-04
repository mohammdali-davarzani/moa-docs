---
sidebar_position: 1
description: flow of bug bounty must to do
---
# Bug Bounty Workflow

## Choosing a Program

- Programs should fit you in, no easy
- Differs for every person, find your path
- I prefer a program to have various functionalities range + older base code
- Change several programs, 10 days, more or less
- After before step choose a main program and stick to it

## Wide Recon

## [Narrow Recon](/docs/category/narrow-recon)

- Applications are like an iceberg
- Narrow recon helps to find more attack surfaces
- Attack surface: where we can find vulnerability in the program

## Threat Modeling

- Preparing potential avenues of attack
- Determining the most effective types of attacks
- Understanding the context and related risks
- Examples:
  - If a reflection occurs, we might try for XSS or SSIT
  - If a URL is being sent, we might try for SSRF
  - If a file uploader is used, try for XSS or RCE
  - If a SQL database is used, we might try SQL injection

## Vulnerability Analysis

- Begin discovering vulnerabilities:
  - By malicious payloads
  - By manipulating workflows
- Security checklists are helpful
- WAF bypass may appear here
- We should be able to perform small research

## Exploitation

- Going forward as much as the policy permits
- We should be able to perform small research

## Reporting

- Vulnerability evaluation based on the CVSS
- Writing a detailed report to show the impact
