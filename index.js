#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { SignJWT, jwtVerify } from "jose";
import express from "express";
import { createServer } from "node:http";
import { randomBytes, randomUUID } from "node:crypto";

class SimpleOAuthProvider {
  constructor(serverUrl, jwtSecret) {
    this.serverUrl = serverUrl;
    this._jwtSecret = new TextEncoder().encode(jwtSecret);
    this._clients = new Map();   // clientId → OAuthClientInformationFull
    this._authCodes = new Map(); // code → { clientId, redirectUri, codeChallenge, expiresAt }

    this.clientsStore = {
      getClient: (clientId) => this._clients.get(clientId),
      registerClient: (client) => {
        this._clients.set(client.client_id, client);
        return client;
      },
    };
  }

  async authorize(client, params, res) {
    const code = randomBytes(32).toString("hex");
    this._authCodes.set(code, {
      clientId: client.client_id,
      redirectUri: params.redirectUri,
      codeChallenge: params.codeChallenge,
      codeChallengeMethod: params.codeChallengeMethod,
      expiresAt: Date.now() + 10 * 60 * 1000,
    });
    const redirectUrl = new URL(params.redirectUri);
    redirectUrl.searchParams.set("code", code);
    if (params.state) redirectUrl.searchParams.set("state", params.state);
    res.redirect(redirectUrl.toString());
  }

  async challengeForAuthorizationCode(_client, authorizationCode) {
    return this._authCodes.get(authorizationCode)?.codeChallenge;
  }

  async exchangeAuthorizationCode(client, authorizationCode) {
    const data = this._authCodes.get(authorizationCode);
    this._authCodes.delete(authorizationCode);
    if (!data || data.expiresAt < Date.now()) throw new Error("Invalid or expired code");

    const accessToken = await new SignJWT({ sub: client.client_id, scope: "" })
      .setProtectedHeader({ alg: "HS256" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(this._jwtSecret);

    return { access_token: accessToken, token_type: "bearer", expires_in: 3600 };
  }

  async exchangeRefreshToken() {
    throw new Error("Refresh tokens not supported");
  }

  async verifyAccessToken(token) {
    const { payload } = await jwtVerify(token, this._jwtSecret);
    return {
      token,
      clientId: String(payload.sub),
      scopes: payload.scope ? String(payload.scope).split(" ") : [],
      expiresAt: payload.exp,
    };
  }
}

class TwentyCRMServer {
  constructor() {
    this.server = new Server(
      {
        name: "twenty-crm",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.apiKey = process.env.TWENTY_API_KEY;
    this.baseUrl = process.env.TWENTY_BASE_URL || "https://api.twenty.com";
    
    if (!this.apiKey) {
      throw new Error("TWENTY_API_KEY environment variable is required");
    }

    this._attachHandlers(this.server);
  }

  async makeRequest(endpoint, method = "GET", data = null) {
    const url = `${this.baseUrl}${endpoint}`;
    const options = {
      method,
      headers: {
        "Authorization": `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
    };

    if (data && (method === "POST" || method === "PUT" || method === "PATCH")) {
      options.body = JSON.stringify(data);
    }

    try {
      const response = await fetch(url, options);
      
      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`HTTP ${response.status}: ${errorText}`);
      }

      const result = await response.json();
      return result;
    } catch (error) {
      throw new Error(`API request failed: ${error.message}`);
    }
  }

  _attachHandlers(server) {
    server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          // People Management
          {
            name: "create_person",
            description: "Create a new person in Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                firstName: { type: "string", description: "First name" },
                lastName: { type: "string", description: "Last name" },
                email: { type: "string", description: "Email address" },
                phone: { type: "string", description: "Phone number" },
                jobTitle: { type: "string", description: "Job title" },
                companyId: { type: "string", description: "Company ID to associate with" },
                linkedinUrl: { type: "string", description: "LinkedIn profile URL" },
                city: { type: "string", description: "City" },
                avatarUrl: { type: "string", description: "Avatar image URL" }
              },
              required: ["firstName", "lastName"]
            }
          },
          {
            name: "get_person",
            description: "Get details of a specific person by ID",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Person ID" }
              },
              required: ["id"]
            }
          },
          {
            name: "update_person",
            description: "Update an existing person's information",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Person ID" },
                firstName: { type: "string", description: "First name" },
                lastName: { type: "string", description: "Last name" },
                email: { type: "string", description: "Email address" },
                phone: { type: "string", description: "Phone number" },
                jobTitle: { type: "string", description: "Job title" },
                companyId: { type: "string", description: "Company ID" },
                linkedinUrl: { type: "string", description: "LinkedIn profile URL" },
                city: { type: "string", description: "City" }
              },
              required: ["id"]
            }
          },
          {
            name: "list_people",
            description: "List people with optional filtering and pagination",
            inputSchema: {
              type: "object",
              properties: {
                limit: { type: "number", description: "Number of results to return (default: 20)" },
                offset: { type: "number", description: "Number of results to skip (default: 0)" },
                search: { type: "string", description: "Search term for name or email" },
                companyId: { type: "string", description: "Filter by company ID" }
              }
            }
          },
          {
            name: "delete_person",
            description: "Delete a person from Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Person ID to delete" }
              },
              required: ["id"]
            }
          },

          // Company Management
          {
            name: "create_company",
            description: "Create a new company in Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                name: { type: "string", description: "Company name" },
                domainName: { type: "string", description: "Company domain" },
                address: { type: "string", description: "Company address" },
                employees: { type: "number", description: "Number of employees" },
                linkedinUrl: { type: "string", description: "LinkedIn company URL" },
                xUrl: { type: "string", description: "X (Twitter) URL" },
                annualRecurringRevenue: { type: "number", description: "Annual recurring revenue" },
                idealCustomerProfile: { type: "boolean", description: "Is this an ideal customer profile" }
              },
              required: ["name"]
            }
          },
          {
            name: "get_company",
            description: "Get details of a specific company by ID",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Company ID" }
              },
              required: ["id"]
            }
          },
          {
            name: "update_company",
            description: "Update an existing company's information",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Company ID" },
                name: { type: "string", description: "Company name" },
                domainName: { type: "string", description: "Company domain" },
                address: { type: "string", description: "Company address" },
                employees: { type: "number", description: "Number of employees" },
                linkedinUrl: { type: "string", description: "LinkedIn company URL" },
                annualRecurringRevenue: { type: "number", description: "Annual recurring revenue" }
              },
              required: ["id"]
            }
          },
          {
            name: "list_companies",
            description: "List companies with optional filtering and pagination",
            inputSchema: {
              type: "object",
              properties: {
                limit: { type: "number", description: "Number of results to return (default: 20)" },
                offset: { type: "number", description: "Number of results to skip (default: 0)" },
                search: { type: "string", description: "Search term for company name" }
              }
            }
          },
          {
            name: "delete_company",
            description: "Delete a company from Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Company ID to delete" }
              },
              required: ["id"]
            }
          },

          // Notes Management
          {
            name: "create_note",
            description: "Create a new note in Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                title: { type: "string", description: "Note title" },
                body: { type: "string", description: "Note content (plain text or markdown)" },
                position: { type: "number", description: "Position for ordering" }
              },
              required: ["title"]
            }
          },
          {
            name: "get_note",
            description: "Get details of a specific note by ID",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Note ID" }
              },
              required: ["id"]
            }
          },
          {
            name: "list_notes",
            description: "List notes with optional filtering and pagination",
            inputSchema: {
              type: "object",
              properties: {
                limit: { type: "number", description: "Number of results to return (default: 20)" },
                offset: { type: "number", description: "Number of results to skip (default: 0)" },
                search: { type: "string", description: "Search term for note title or content" }
              }
            }
          },
          {
            name: "update_note",
            description: "Update an existing note",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Note ID" },
                title: { type: "string", description: "Note title" },
                body: { type: "string", description: "Note content" },
                position: { type: "number", description: "Position for ordering" }
              },
              required: ["id"]
            }
          },
          {
            name: "delete_note",
            description: "Delete a note from Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Note ID to delete" }
              },
              required: ["id"]
            }
          },

          // Tasks Management
          {
            name: "create_task",
            description: "Create a new task in Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                title: { type: "string", description: "Task title" },
                body: { type: "string", description: "Task description" },
                dueAt: { type: "string", description: "Due date (ISO 8601 format)" },
                status: { type: "string", description: "Task status", enum: ["TODO", "IN_PROGRESS", "DONE"] },
                assigneeId: { type: "string", description: "ID of person assigned to task" },
                position: { type: "number", description: "Position for ordering" }
              },
              required: ["title"]
            }
          },
          {
            name: "get_task",
            description: "Get details of a specific task by ID",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Task ID" }
              },
              required: ["id"]
            }
          },
          {
            name: "list_tasks",
            description: "List tasks with optional filtering and pagination",
            inputSchema: {
              type: "object",
              properties: {
                limit: { type: "number", description: "Number of results to return (default: 20)" },
                offset: { type: "number", description: "Number of results to skip (default: 0)" },
                status: { type: "string", description: "Filter by status", enum: ["TODO", "IN_PROGRESS", "DONE"] },
                assigneeId: { type: "string", description: "Filter by assignee ID" }
              }
            }
          },
          {
            name: "update_task",
            description: "Update an existing task",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Task ID" },
                title: { type: "string", description: "Task title" },
                body: { type: "string", description: "Task description" },
                dueAt: { type: "string", description: "Due date (ISO 8601 format)" },
                status: { type: "string", description: "Task status", enum: ["TODO", "IN_PROGRESS", "DONE"] },
                assigneeId: { type: "string", description: "ID of person assigned to task" }
              },
              required: ["id"]
            }
          },
          {
            name: "delete_task",
            description: "Delete a task from Twenty CRM",
            inputSchema: {
              type: "object",
              properties: {
                id: { type: "string", description: "Task ID to delete" }
              },
              required: ["id"]
            }
          },

          // Metadata Operations
          {
            name: "get_metadata_objects",
            description: "Get all object types and their metadata",
            inputSchema: {
              type: "object",
              properties: {}
            }
          },
          {
            name: "get_object_metadata",
            description: "Get metadata for a specific object type",
            inputSchema: {
              type: "object",
              properties: {
                objectName: { type: "string", description: "Object name (e.g., 'people', 'companies')" }
              },
              required: ["objectName"]
            }
          },

          // Search and Enrichment
          {
            name: "search_records",
            description: "Search across multiple object types",
            inputSchema: {
              type: "object",
              properties: {
                query: { type: "string", description: "Search query" },
                objectTypes: {
                  type: "array",
                  items: { type: "string" },
                  description: "Object types to search (e.g., ['people', 'companies'])"
                },
                limit: { type: "number", description: "Number of results per object type" }
              },
              required: ["query"]
            }
          },

          // Custom / Generic Object Operations
          {
            name: "create_record",
            description: "Create a record of any object type, including custom objects (e.g. kontentPlan, products, deals)",
            inputSchema: {
              type: "object",
              properties: {
                objectType: { type: "string", description: "Plural API name of the object (e.g. 'kontentPlans', 'products')" },
                data: { type: "object", description: "Field values for the new record" }
              },
              required: ["objectType", "data"]
            }
          },
          {
            name: "list_records",
            description: "List records of any object type, including custom objects",
            inputSchema: {
              type: "object",
              properties: {
                objectType: { type: "string", description: "Plural API name of the object (e.g. 'kontentPlans', 'products')" },
                limit: { type: "number", description: "Number of results (default: 20)" },
                offset: { type: "number", description: "Number of results to skip (default: 0)" },
                filter: { type: "string", description: "Filter string to append to the query" }
              },
              required: ["objectType"]
            }
          },
          {
            name: "get_record",
            description: "Get a single record of any object type by ID",
            inputSchema: {
              type: "object",
              properties: {
                objectType: { type: "string", description: "Plural API name of the object (e.g. 'kontentPlans', 'products')" },
                id: { type: "string", description: "Record ID" }
              },
              required: ["objectType", "id"]
            }
          },
          {
            name: "update_record",
            description: "Update a record of any object type by ID",
            inputSchema: {
              type: "object",
              properties: {
                objectType: { type: "string", description: "Plural API name of the object (e.g. 'kontentPlans', 'products')" },
                id: { type: "string", description: "Record ID" },
                data: { type: "object", description: "Fields to update" }
              },
              required: ["objectType", "id", "data"]
            }
          },
          {
            name: "delete_record",
            description: "Delete a record of any object type by ID",
            inputSchema: {
              type: "object",
              properties: {
                objectType: { type: "string", description: "Plural API name of the object (e.g. 'kontentPlans', 'products')" },
                id: { type: "string", description: "Record ID" }
              },
              required: ["objectType", "id"]
            }
          }
        ]
      };
    });

    server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          // People operations
          case "create_person":
            return await this.createPerson(args);
          case "get_person":
            return await this.getPerson(args.id);
          case "update_person":
            return await this.updatePerson(args);
          case "list_people":
            return await this.listPeople(args);
          case "delete_person":
            return await this.deletePerson(args.id);

          // Company operations
          case "create_company":
            return await this.createCompany(args);
          case "get_company":
            return await this.getCompany(args.id);
          case "update_company":
            return await this.updateCompany(args);
          case "list_companies":
            return await this.listCompanies(args);
          case "delete_company":
            return await this.deleteCompany(args.id);

          // Note operations
          case "create_note":
            return await this.createNote(args);
          case "get_note":
            return await this.getNote(args.id);
          case "list_notes":
            return await this.listNotes(args);
          case "update_note":
            return await this.updateNote(args);
          case "delete_note":
            return await this.deleteNote(args.id);

          // Task operations
          case "create_task":
            return await this.createTask(args);
          case "get_task":
            return await this.getTask(args.id);
          case "list_tasks":
            return await this.listTasks(args);
          case "update_task":
            return await this.updateTask(args);
          case "delete_task":
            return await this.deleteTask(args.id);

          // Metadata operations
          case "get_metadata_objects":
            return await this.getMetadataObjects();
          case "get_object_metadata":
            return await this.getObjectMetadata(args.objectName);

          // Search operations
          case "search_records":
            return await this.searchRecords(args);

          // Generic / custom object operations
          case "create_record":
            return await this.createRecord(args);
          case "list_records":
            return await this.listRecords(args);
          case "get_record":
            return await this.getRecord(args);
          case "update_record":
            return await this.updateRecord(args);
          case "delete_record":
            return await this.deleteRecord(args);

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message}`
            }
          ]
        };
      }
    });
  }

  // People methods
  async createPerson(data) {
    const result = await this.makeRequest("/rest/people", "POST", data);
    return {
      content: [
        {
          type: "text",
          text: `Created person: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async getPerson(id) {
    const result = await this.makeRequest(`/rest/people/${id}`);
    return {
      content: [
        {
          type: "text",
          text: `Person details: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async updatePerson(data) {
    const { id, ...updateData } = data;
    const result = await this.makeRequest(`/rest/people/${id}`, "PUT", updateData);
    return {
      content: [
        {
          type: "text",
          text: `Updated person: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async listPeople(params = {}) {
    const { limit = 20, offset = 0, search, companyId } = params;
    let endpoint = `/rest/people?limit=${limit}&offset=${offset}`;
    
    if (search) {
      endpoint += `&search=${encodeURIComponent(search)}`;
    }
    if (companyId) {
      endpoint += `&companyId=${companyId}`;
    }

    const result = await this.makeRequest(endpoint);
    return {
      content: [
        {
          type: "text",
          text: `People list: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async deletePerson(id) {
    await this.makeRequest(`/rest/people/${id}`, "DELETE");
    return {
      content: [
        {
          type: "text",
          text: `Successfully deleted person with ID: ${id}`
        }
      ]
    };
  }

  // Company methods
  async createCompany(data) {
    const result = await this.makeRequest("/rest/companies", "POST", data);
    return {
      content: [
        {
          type: "text",
          text: `Created company: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async getCompany(id) {
    const result = await this.makeRequest(`/rest/companies/${id}`);
    return {
      content: [
        {
          type: "text",
          text: `Company details: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async updateCompany(data) {
    const { id, ...updateData } = data;
    const result = await this.makeRequest(`/rest/companies/${id}`, "PUT", updateData);
    return {
      content: [
        {
          type: "text",
          text: `Updated company: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async listCompanies(params = {}) {
    const { limit = 20, offset = 0, search } = params;
    let endpoint = `/rest/companies?limit=${limit}&offset=${offset}`;
    
    if (search) {
      endpoint += `&search=${encodeURIComponent(search)}`;
    }

    const result = await this.makeRequest(endpoint);
    return {
      content: [
        {
          type: "text",
          text: `Companies list: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async deleteCompany(id) {
    await this.makeRequest(`/rest/companies/${id}`, "DELETE");
    return {
      content: [
        {
          type: "text",
          text: `Successfully deleted company with ID: ${id}`
        }
      ]
    };
  }

  // Note methods
  async createNote(data) {
    const { body, ...rest } = data;
    const payload = { ...rest };
    if (body) {
      payload.bodyV2 = { markdown: body };
    }
    const result = await this.makeRequest("/rest/notes", "POST", payload);
    return {
      content: [
        {
          type: "text",
          text: `Created note: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async getNote(id) {
    const result = await this.makeRequest(`/rest/notes/${id}`);
    return {
      content: [
        {
          type: "text",
          text: `Note details: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async listNotes(params = {}) {
    const { limit = 20, offset = 0, search } = params;
    let endpoint = `/rest/notes?limit=${limit}&offset=${offset}`;
    
    if (search) {
      endpoint += `&search=${encodeURIComponent(search)}`;
    }

    const result = await this.makeRequest(endpoint);
    return {
      content: [
        {
          type: "text",
          text: `Notes list: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async updateNote(data) {
    const { id, body, ...rest } = data;
    const updateData = { ...rest };
    if (body) {
      updateData.bodyV2 = { markdown: body };
    }
    const result = await this.makeRequest(`/rest/notes/${id}`, "PATCH", updateData);
    return {
      content: [
        {
          type: "text",
          text: `Updated note: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async deleteNote(id) {
    await this.makeRequest(`/rest/notes/${id}`, "DELETE");
    return {
      content: [
        {
          type: "text",
          text: `Successfully deleted note with ID: ${id}`
        }
      ]
    };
  }

  // Task methods
  async createTask(data) {
    const result = await this.makeRequest("/rest/tasks", "POST", data);
    return {
      content: [
        {
          type: "text",
          text: `Created task: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async getTask(id) {
    const result = await this.makeRequest(`/rest/tasks/${id}`);
    return {
      content: [
        {
          type: "text",
          text: `Task details: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async listTasks(params = {}) {
    const { limit = 20, offset = 0, status, assigneeId } = params;
    let endpoint = `/rest/tasks?limit=${limit}&offset=${offset}`;
    
    if (status) {
      endpoint += `&status=${status}`;
    }
    if (assigneeId) {
      endpoint += `&assigneeId=${assigneeId}`;
    }

    const result = await this.makeRequest(endpoint);
    return {
      content: [
        {
          type: "text",
          text: `Tasks list: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async updateTask(data) {
    const { id, ...updateData } = data;
    const result = await this.makeRequest(`/rest/tasks/${id}`, "PUT", updateData);
    return {
      content: [
        {
          type: "text",
          text: `Updated task: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async deleteTask(id) {
    await this.makeRequest(`/rest/tasks/${id}`, "DELETE");
    return {
      content: [
        {
          type: "text",
          text: `Successfully deleted task with ID: ${id}`
        }
      ]
    };
  }

  // Metadata methods
  async getMetadataObjects() {
    const result = await this.makeRequest("/rest/metadata/objects");
    return {
      content: [
        {
          type: "text",
          text: `Metadata objects: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  async getObjectMetadata(objectName) {
    const result = await this.makeRequest(`/rest/metadata/objects/${objectName}`);
    return {
      content: [
        {
          type: "text",
          text: `Metadata for ${objectName}: ${JSON.stringify(result, null, 2)}`
        }
      ]
    };
  }

  // Generic / custom object methods
  async createRecord({ objectType, data }) {
    const result = await this.makeRequest(`/rest/${objectType}`, "POST", data);
    return { content: [{ type: "text", text: `Created ${objectType} record: ${JSON.stringify(result, null, 2)}` }] };
  }

  async listRecords({ objectType, limit = 20, offset = 0, filter }) {
    let endpoint = `/rest/${objectType}?limit=${limit}&offset=${offset}`;
    if (filter) endpoint += `&${filter}`;
    const result = await this.makeRequest(endpoint);
    return { content: [{ type: "text", text: `${objectType} records: ${JSON.stringify(result, null, 2)}` }] };
  }

  async getRecord({ objectType, id }) {
    const result = await this.makeRequest(`/rest/${objectType}/${id}`);
    return { content: [{ type: "text", text: `${objectType} record: ${JSON.stringify(result, null, 2)}` }] };
  }

  async updateRecord({ objectType, id, data }) {
    const result = await this.makeRequest(`/rest/${objectType}/${id}`, "PATCH", data);
    return { content: [{ type: "text", text: `Updated ${objectType} record: ${JSON.stringify(result, null, 2)}` }] };
  }

  async deleteRecord({ objectType, id }) {
    await this.makeRequest(`/rest/${objectType}/${id}`, "DELETE");
    return { content: [{ type: "text", text: `Deleted ${objectType} record with ID: ${id}` }] };
  }

  // Search methods
  async searchRecords(params) {
    const { query, objectTypes = ['people', 'companies'], limit = 10 } = params;
    const results = {};

    for (const objectType of objectTypes) {
      try {
        const endpoint = `/rest/${objectType}?search=${encodeURIComponent(query)}&limit=${limit}`;
        results[objectType] = await this.makeRequest(endpoint);
      } catch (error) {
        results[objectType] = { error: error.message };
      }
    }

    return {
      content: [
        {
          type: "text",
          text: `Search results for "${query}": ${JSON.stringify(results, null, 2)}`
        }
      ]
    };
  }

  async run() {
    const mode = process.env.TRANSPORT_MODE || "stdio";

    if (mode === "stdio") {
      const transport = new StdioServerTransport();
      await this.server.connect(transport);
      console.error("Twenty CRM MCP server running on stdio");
      return;
    }

    // Streamable HTTP + OAuth mode
    const app = express();
    const port = parseInt(process.env.PORT || "3000", 10);
    const serverUrl = new URL(process.env.MCP_SERVER_URL || `http://localhost:${port}`);
    const jwtSecret = process.env.MCP_AUTH_TOKEN || randomBytes(32).toString("hex");

    // Parse JSON bodies — required for /register, /token and /mcp POST
    app.use(express.json());

    // CORS — Claude.ai is a browser app, needs cross-origin headers
    app.use((req, res, next) => {
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader(
        "Access-Control-Allow-Headers",
        "Authorization, Content-Type, Mcp-Session-Id, Last-Event-Id, Mcp-Protocol-Version"
      );
      res.setHeader(
        "Access-Control-Expose-Headers",
        "WWW-Authenticate, Mcp-Session-Id"
      );
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
      if (req.method === "OPTIONS") return res.sendStatus(204);
      next();
    });

    const oauthProvider = new SimpleOAuthProvider(serverUrl, jwtSecret);

    // OAuth endpoints: /.well-known/oauth-protected-resource,
    //                  /.well-known/oauth-authorization-server,
    //                  GET /authorize, POST /register, POST /token
    app.use(mcpAuthRouter({ provider: oauthProvider, issuerUrl: serverUrl }));

    const authMiddleware = requireBearerAuth({ verifier: oauthProvider });

    const transports = {}; // sessionId → StreamableHTTPServerTransport

    app.get("/health", (_req, res) => res.json({ status: "ok", server: "twenty-crm-mcp" }));

    const mcpHandler = async (req, res) => {
      try {
        const sessionId = req.headers["mcp-session-id"];

        if (sessionId && transports[sessionId]) {
          await transports[sessionId].handleRequest(req, res, req.body);
          return;
        }

        if (!sessionId && req.method === "POST") {
          const transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: (sid) => { transports[sid] = transport; },
          });
          transport.onclose = () => {
            if (transport.sessionId) delete transports[transport.sessionId];
          };
          const mcpServer = new Server(
            { name: "twenty-crm", version: "0.1.0" },
            { capabilities: { tools: {} } }
          );
          this._attachHandlers(mcpServer);
          await mcpServer.connect(transport);
          await transport.handleRequest(req, res, req.body);
          return;
        }

        res.status(400).json({ error: "Invalid request: missing or unknown session" });
      } catch (err) {
        console.error("[MCP] handler error:", err);
        if (!res.headersSent) res.status(500).json({ error: "Internal server error" });
      }
    };

    app.post("/mcp", authMiddleware, mcpHandler);
    app.get("/mcp", authMiddleware, mcpHandler);
    app.delete("/mcp", authMiddleware, mcpHandler);

    createServer(app).listen(port, () =>
      console.error(`Twenty CRM MCP (Streamable HTTP + OAuth) listening on port ${port}`)
    );
  }
}

const server = new TwentyCRMServer();
server.run().catch(console.error);