<div align="center">

<img src="https://avatars.githubusercontent.com/u/222849293?s=200&v=4" width="96" alt="Ellum AI" />

# Ellum AI

**We build AI that does the work — not just the talking.**

Two products, one idea: put capable agents where the work actually happens.

[![Website](https://img.shields.io/badge/ellum.ai-000000?style=for-the-badge&logo=googlechrome&logoColor=white)](https://www.ellum.ai)
[![App](https://img.shields.io/badge/app.ellum.ai-1a1a1a?style=for-the-badge&logo=vercel&logoColor=white)](https://app.ellum.ai)
[![Deep Ellum](https://img.shields.io/badge/deepellum.ai-4c1d95?style=for-the-badge&logo=openai&logoColor=white)](https://deepellum.ai)

</div>

---

## What we're building

### 🪄 Ellum AI — AI-powered social media management

An end-to-end workspace for teams who publish. Plan, create, schedule, and measure —
with an AI assistant and a roster of agents working alongside you rather than in a
separate tab.

|  | |
| --- | --- |
| **Content & calendar** | Draft, review, and schedule across connected social accounts |
| **AI assistant** | A workspace-wide agent with typed tools that can act on your content, not just describe it |
| **AI staff & agent hub** | Staff agents to recurring jobs, then watch them work — inbox, network, and logs included |
| **Comments & analytics** | Engagement and performance in the same place you planned the post |
| **Knowledge center & teams** | Shared context and per-organization roles, so agents know your brand |

→ **[www.ellum.ai](https://www.ellum.ai)** · Sign in at **[app.ellum.ai](https://app.ellum.ai)**

### 🌐 Deep Ellum — an AI agent marketplace

Discover, install, and run agents without building the plumbing. Deep research with
live web grounding, content planning, and custom chatbots — reachable from our
dashboard, from your own stack via API, or from any MCP-compatible AI assistant.

A CLI and TypeScript client are in the works for driving the same agents from your
terminal and your own code.

→ **[deepellum.ai](https://deepellum.ai)**

---

## How it's made

<div align="center">

![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js%2016-000000?style=flat-square&logo=nextdotjs&logoColor=white)
![React](https://img.shields.io/badge/React%2019-61DAFB?style=flat-square&logo=react&logoColor=black)
![Tailwind CSS](https://img.shields.io/badge/Tailwind%20v4-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)
![Expo](https://img.shields.io/badge/Expo-000020?style=flat-square&logo=expo&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white)
![LangChain](https://img.shields.io/badge/LangChain-1C3C3C?style=flat-square&logo=langchain&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?style=flat-square&logo=docker&logoColor=white)

</div>

- **Front of house** — Next.js 16 (App Router, Cache Components) and React 19 on the
  web, Expo and React Native on mobile, Tailwind v4 + shadcn throughout.
- **Agents** — the Vercel AI SDK for tool-calling agent loops in the product, and a
  Python service on FastAPI + LangChain behind it. Model-agnostic by design: OpenAI
  and Google Gemini are both first-class, chosen by configuration.
- **Real-time** — streaming responses over SSE and WebSockets, with Celery and Redis
  handling the work that shouldn't block a request.
- **Integrations** — social platforms, Slack, and the Model Context Protocol, so our
  agents show up as tools inside other assistants too.

---

## Working with us

Our product repositories are private while we build, so this org page is quieter than
the work behind it. The fastest way to see what we do is to
**[try the app](https://app.ellum.ai)** or **[browse the agent catalog](https://deepellum.ai)**.

Interested in joining, integrating, or partnering? Reach us through
**[ellum.ai](https://www.ellum.ai)**.

<div align="center">
<sub>Built by the team at Ellum AI</sub>
</div>
