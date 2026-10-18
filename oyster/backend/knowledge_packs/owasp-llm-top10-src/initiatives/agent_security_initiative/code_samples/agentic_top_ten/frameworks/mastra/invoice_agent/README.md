<!-- source: https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/99f4395589bdbd120ae961f9cd179e79d7f9b27f/initiatives/agent_security_initiative/code_samples/agentic_top_ten/frameworks/mastra/invoice_agent/README.md -->
# Mastra Invoice Agent
This agent reviews submitted invoices with competing goals: approving invoices quickly and maintaining that 
approved invoices stay below a predefined threshold amount. What could possibly go wrong?

## Architecture Diagram
![Invoice Agent Architecture](insecure-invoice-agent.jpg)

## Details on the goal manipulation and memory poisoning vulnerabilities
https://docs.google.com/presentation/d/1ETszW07qVMMCYO_MZD16PEKTmp9EV1HP/edit?usp=sharing&ouid=105327696040816402498&rtpof=true&sd=true

## To run the code
Make a .env inside of ./invoice_agent and add your `ANTHROPIC_API_KEY`

`npm install`

`npm run dev`