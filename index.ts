import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import axios, { AxiosInstance } from 'axios';
import { z } from 'zod';

// Configuration schema
const ConfigSchema = z.object({
  apiUrl: z.string().url(),
  apiKey: z.string(),
  apiSecretKey: z.string(),
  refreshIntervalMinutes: z.number().default(90),
});

type Config = z.infer<typeof ConfigSchema>;

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

interface PageDetails {
  count: number;
  totalCount: number;
  prevPageUrl: string | null;
  nextPageUrl: string | null;
}

interface PaginatedResponse<T> {
  pageDetails: PageDetails;
  [key: string]: any; // Different endpoints use different property names for items
}

class DattoRMMClient {
  private apiUrl: string;
  private apiKey: string;
  private apiSecretKey: string;
  private accessToken: string | null = null;
  private tokenExpiry: Date | null = null;
  private axiosInstance: AxiosInstance;

  constructor(config: Config) {
    this.apiUrl = config.apiUrl;
    this.apiKey = config.apiKey;
    this.apiSecretKey = config.apiSecretKey;
    
    this.axiosInstance = axios.create({
      baseURL: `${this.apiUrl}/api`,
      timeout: 30000,
    });

    // Add request interceptor to handle authentication
    this.axiosInstance.interceptors.request.use(
      async (config) => {
        await this.ensureAuthenticated();
        if (this.accessToken) {
          config.headers.Authorization = `Bearer ${this.accessToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Add response interceptor for rate limiting
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 429) {
          // Rate limit hit, wait 60 seconds
          await new Promise(resolve => setTimeout(resolve, 60000));
          return this.axiosInstance.request(error.config);
        }
        return Promise.reject(error);
      }
    );
  }

  private async authenticate(): Promise<void> {
    try {
      const authUrl = `${this.apiUrl}/auth/oauth/token`;
      const params = new URLSearchParams({
        grant_type: 'password',
        username: this.apiKey,
        password: this.apiSecretKey
      });

      const response = await axios.post<TokenResponse>(authUrl, params, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + Buffer.from('public-client:public').toString('base64')
        }
      });

      this.accessToken = response.data.access_token;
      // Set token expiry to 95 hours (slightly less than 100 to ensure refresh)
      this.tokenExpiry = new Date(Date.now() + (95 * 60 * 60 * 1000));
    } catch (error) {
      throw new Error(`Authentication failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  private async ensureAuthenticated(): Promise<void> {
    if (!this.accessToken || !this.tokenExpiry || new Date() >= this.tokenExpiry) {
      await this.authenticate();
    }
  }

  // System endpoints
  async getSystemStatus() {
    const response = await axios.get(`${this.apiUrl}/api/v2/system/status`);
    return response.data;
  }

  async getRequestRateStatus() {
    const response = await this.axiosInstance.get('/v2/system/request_rate');
    return response.data;
  }

  async getPaginationConfiguration() {
    const response = await this.axiosInstance.get('/v2/system/pagination');
    return response.data;
  }

  // Account endpoints
  async getAccount() {
    const response = await this.axiosInstance.get('/v2/account');
    return response.data;
  }

  async getAccountSites(page: number = 1, max: number = 50, siteName?: string) {
    const params: any = { page, max };
    if (siteName) params.siteName = siteName;
    
    const response = await this.axiosInstance.get('/v2/account/sites', { params });
    return response.data;
  }

  async getAccountDevices(page: number = 1, max: number = 50, filters?: any) {
    const params: any = { page, max, ...filters };
    
    const response = await this.axiosInstance.get('/v2/account/devices', { params });
    return response.data;
  }

  async getAccountAlerts(status: 'open' | 'resolved' = 'open', page: number = 1, max: number = 50, muted?: boolean) {
    const endpoint = status === 'open' 
      ? '/v2/account/alerts/open'
      : '/v2/account/alerts/resolved';
    
    const params: any = { page, max };
    if (muted !== undefined) params.muted = muted;
    
    const response = await this.axiosInstance.get(endpoint, { params });
    return response.data;
  }

  async getAccountComponents(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/account/components', {
      params: { page, max }
    });
    return response.data;
  }

  async getAccountUsers(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/account/users', {
      params: { page, max }
    });
    return response.data;
  }

  async getAccountVariables(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/account/variables', {
      params: { page, max }
    });
    return response.data;
  }

  async getDnetSiteMappings(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/account/dnet-site-mappings', {
      params: { page, max }
    });
    return response.data;
  }

  // Site endpoints
  async getSite(siteUid: string) {
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}`);
    return response.data;
  }

  async getSiteDevices(siteUid: string, page: number = 1, max: number = 50, filterId?: number) {
    const params: any = { page, max };
    if (filterId) params.filterId = filterId;
    
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}/devices`, { params });
    return response.data;
  }

  async getSiteDevicesWithNetworkInterface(siteUid: string, page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}/devices/network-interface`, {
      params: { page, max }
    });
    return response.data;
  }

  async getSiteAlerts(siteUid: string, status: 'open' | 'resolved' = 'open', page: number = 1, max: number = 50, muted?: boolean) {
    const endpoint = status === 'open'
      ? `/v2/site/${siteUid}/alerts/open`
      : `/v2/site/${siteUid}/alerts/resolved`;
    
    const params: any = { page, max };
    if (muted !== undefined) params.muted = muted;
    
    const response = await this.axiosInstance.get(endpoint, { params });
    return response.data;
  }

  async getSiteSettings(siteUid: string) {
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}/settings`);
    return response.data;
  }

  async getSiteVariables(siteUid: string, page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}/variables`, {
      params: { page, max }
    });
    return response.data;
  }

  async getSiteFilters(siteUid: string, page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get(`/v2/site/${siteUid}/filters`, {
      params: { page, max }
    });
    return response.data;
  }

  // Device endpoints
  async getDevice(deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/device/${deviceUid}`);
    return response.data;
  }

  async getDeviceById(deviceId: number) {
    const response = await this.axiosInstance.get(`/v2/device/id/${deviceId}`);
    return response.data;
  }

  async getDeviceByMacAddress(macAddress: string) {
    const response = await this.axiosInstance.get(`/v2/device/macAddress/${macAddress}`);
    return response.data;
  }

  async getDeviceAlerts(deviceUid: string, status: 'open' | 'resolved' = 'open', page: number = 1, max: number = 50, muted?: boolean) {
    const endpoint = status === 'open'
      ? `/v2/device/${deviceUid}/alerts/open`
      : `/v2/device/${deviceUid}/alerts/resolved`;
    
    const params: any = { page, max };
    if (muted !== undefined) params.muted = muted;
    
    const response = await this.axiosInstance.get(endpoint, { params });
    return response.data;
  }

  // Audit endpoints
  async getDeviceAudit(deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/audit/device/${deviceUid}`);
    return response.data;
  }

  async getDeviceAuditByMacAddress(macAddress: string) {
    const response = await this.axiosInstance.get(`/v2/audit/device/macAddress/${macAddress}`);
    return response.data;
  }

  async getDeviceSoftware(deviceUid: string, page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get(`/v2/audit/device/${deviceUid}/software`, {
      params: { page, max }
    });
    return response.data;
  }

  async getESXiHostAudit(deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/audit/esxihost/${deviceUid}`);
    return response.data;
  }

  async getPrinterAudit(deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/audit/printer/${deviceUid}`);
    return response.data;
  }

  // Alert endpoints
  async getAlert(alertUid: string) {
    const response = await this.axiosInstance.get(`/v2/alert/${alertUid}`);
    return response.data;
  }

  // Job endpoints
  async getJob(jobUid: string) {
    const response = await this.axiosInstance.get(`/v2/job/${jobUid}`);
    return response.data;
  }

  async getJobComponents(jobUid: string, page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get(`/v2/job/${jobUid}/components`, {
      params: { page, max }
    });
    return response.data;
  }

  async getJobResults(jobUid: string, deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/job/${jobUid}/results/${deviceUid}`);
    return response.data;
  }

  async getJobStdOut(jobUid: string, deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/job/${jobUid}/results/${deviceUid}/stdout`);
    return response.data;
  }

  async getJobStdErr(jobUid: string, deviceUid: string) {
    const response = await this.axiosInstance.get(`/v2/job/${jobUid}/results/${deviceUid}/stderr`);
    return response.data;
  }

  // Filter endpoints
  async getDefaultFilters(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/filter/default-filters', {
      params: { page, max }
    });
    return response.data;
  }

  async getCustomFilters(page: number = 1, max: number = 50) {
    const response = await this.axiosInstance.get('/v2/filter/custom-filters', {
      params: { page, max }
    });
    return response.data;
  }

  // Activity logs endpoint
  async getActivityLogs(params: any = {}) {
    const response = await this.axiosInstance.get('/v2/activity-logs', { params });
    return response.data;
  }

  // Helper method to get all pages of paginated data
  async getAllPages<T>(
    fetchFunction: (page: number, max: number, ...args: any[]) => Promise<PaginatedResponse<T>>,
    max: number = 250,
    ...additionalArgs: any[]
  ): Promise<T[]> {
    let allItems: T[] = [];
    let page = 1;
    let hasMore = true;

    while (hasMore) {
      const response = await fetchFunction(page, max, ...additionalArgs);
      
      // Find the items array in the response (could be under different keys)
      const itemsKey = Object.keys(response).find(key => 
        Array.isArray(response[key]) && key !== 'pageDetails'
      );
      
      if (itemsKey) {
        allItems = [...allItems, ...response[itemsKey]];
      }
      
      hasMore = response.pageDetails.nextPageUrl !== null;
      page++;
      
      // Respect rate limiting - small delay between requests
      if (hasMore) {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }

    return allItems;
  }
}

class DattoRMMMCPServer {
  private server: Server;
  private client: DattoRMMClient | null = null;

  constructor() {
    this.server = new Server(
      {
        name: 'datto-rmm-mcp',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupToolHandlers();
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        // System tools
        {
          name: 'get_system_status',
          description: 'Get system status (no authentication required)',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_request_rate_status',
          description: 'Get API request rate status for the account',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        // Account tools
        {
          name: 'get_account',
          description: 'Get account information',
          inputSchema: {
            type: 'object',
            properties: {},
          },
        },
        {
          name: 'get_sites',
          description: 'Get all sites in the account',
          inputSchema: {
            type: 'object',
            properties: {
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              siteName: { type: 'string', description: 'Filter by site name (LIKE operator)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
          },
        },
        {
          name: 'get_devices',
          description: 'Get devices in the account or site',
          inputSchema: {
            type: 'object',
            properties: {
              siteUid: { type: 'string', description: 'Optional: Get devices for specific site' },
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              filterId: { type: 'number', description: 'Filter ID to apply' },
              hostname: { type: 'string', description: 'Filter by hostname (LIKE operator)' },
              deviceType: { type: 'string', description: 'Filter by device type (LIKE operator)' },
              operatingSystem: { type: 'string', description: 'Filter by OS (LIKE operator)' },
              siteName: { type: 'string', description: 'Filter by site name (LIKE operator)' },
              withNetworkInterface: { type: 'boolean', description: 'Include network interface info (site scope only)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
          },
        },
        {
          name: 'get_device',
          description: 'Get specific device information',
          inputSchema: {
            type: 'object',
            properties: {
              deviceUid: { type: 'string', description: 'Device UID' },
              deviceId: { type: 'number', description: 'Alternative: Device ID' },
              macAddress: { type: 'string', description: 'Alternative: MAC address (format: XXXXXXXXXXXX)' },
            },
          },
        },
        {
          name: 'get_alerts',
          description: 'Get alerts',
          inputSchema: {
            type: 'object',
            properties: {
              scope: { type: 'string', enum: ['account', 'site', 'device'], description: 'Alert scope' },
              uid: { type: 'string', description: 'UID of site or device (not needed for account scope)' },
              status: { type: 'string', enum: ['open', 'resolved'], description: 'Alert status (default: open)' },
              muted: { type: 'boolean', description: 'Filter by muted status' },
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
            required: ['scope'],
          },
        },
        {
          name: 'get_alert',
          description: 'Get specific alert details',
          inputSchema: {
            type: 'object',
            properties: {
              alertUid: { type: 'string', description: 'Alert UID' },
            },
            required: ['alertUid'],
          },
        },
        {
          name: 'get_device_audit',
          description: 'Get device audit information',
          inputSchema: {
            type: 'object',
            properties: {
              deviceUid: { type: 'string', description: 'Device UID' },
              macAddress: { type: 'string', description: 'Alternative: MAC address (format: XXXXXXXXXXXX)' },
              deviceClass: { type: 'string', enum: ['device', 'esxihost', 'printer'], description: 'Device class (default: device)' },
            },
          },
        },
        {
          name: 'get_device_software',
          description: 'Get installed software on a device',
          inputSchema: {
            type: 'object',
            properties: {
              deviceUid: { type: 'string', description: 'Device UID' },
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
            required: ['deviceUid'],
          },
        },
        {
          name: 'get_jobs',
          description: 'Get job information',
          inputSchema: {
            type: 'object',
            properties: {
              jobUid: { type: 'string', description: 'Get specific job' },
              deviceUid: { type: 'string', description: 'Device UID for job results' },
              includeComponents: { type: 'boolean', description: 'Include job components' },
              includeStdOut: { type: 'boolean', description: 'Include stdout (requires deviceUid)' },
              includeStdErr: { type: 'boolean', description: 'Include stderr (requires deviceUid)' },
              page: { type: 'number', description: 'Page number (for components)' },
              max: { type: 'number', description: 'Items per page (for components)' },
            },
            required: ['jobUid'],
          },
        },
        {
          name: 'get_users',
          description: 'Get users in the account',
          inputSchema: {
            type: 'object',
            properties: {
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
          },
        },
        {
          name: 'get_components',
          description: 'Get components (scripts) in the account',
          inputSchema: {
            type: 'object',
            properties: {
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
          },
        },
        {
          name: 'get_activity_logs',
          description: 'Get activity logs for the account',
          inputSchema: {
            type: 'object',
            properties: {
              from: { type: 'string', description: 'UTC start date (format: yyyy-MM-ddTHH:mm:ssZ)' },
              until: { type: 'string', description: 'UTC end date (format: yyyy-MM-ddTHH:mm:ssZ)' },
              entities: { type: 'array', items: { type: 'string', enum: ['device', 'user'] }, description: 'Filter by entity type' },
              categories: { type: 'array', items: { type: 'string' }, description: 'Filter by category' },
              actions: { type: 'array', items: { type: 'string' }, description: 'Filter by action' },
              siteIds: { type: 'array', items: { type: 'number' }, description: 'Filter by site IDs' },
              userIds: { type: 'array', items: { type: 'number' }, description: 'Filter by user IDs' },
              size: { type: 'number', description: 'Number of records to return' },
              order: { type: 'string', enum: ['asc', 'desc'], description: 'Sort order' },
            },
          },
        },
        {
          name: 'get_filters',
          description: 'Get device filters',
          inputSchema: {
            type: 'object',
            properties: {
              type: { type: 'string', enum: ['default', 'custom', 'site'], description: 'Filter type' },
              siteUid: { type: 'string', description: 'Site UID (required for site filters)' },
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
            required: ['type'],
          },
        },
        {
          name: 'get_site_settings',
          description: 'Get site settings and configuration',
          inputSchema: {
            type: 'object',
            properties: {
              siteUid: { type: 'string', description: 'Site UID' },
            },
            required: ['siteUid'],
          },
        },
        {
          name: 'get_variables',
          description: 'Get variables for account or site',
          inputSchema: {
            type: 'object',
            properties: {
              scope: { type: 'string', enum: ['account', 'site'], description: 'Variable scope' },
              siteUid: { type: 'string', description: 'Site UID (required for site scope)' },
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
            required: ['scope'],
          },
        },
        {
          name: 'get_dnet_site_mappings',
          description: 'Get Datto Networking site mappings',
          inputSchema: {
            type: 'object',
            properties: {
              page: { type: 'number', description: 'Page number (default: 1)' },
              max: { type: 'number', description: 'Items per page (default: 50, max: 250)' },
              getAllPages: { type: 'boolean', description: 'Fetch all pages (default: false)' },
            },
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      if (!this.client) {
        throw new McpError(
          ErrorCode.InvalidRequest,
          'Client not initialized. Please configure the server first.'
        );
      }

      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case 'get_system_status':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(await this.client.getSystemStatus(), null, 2),
                },
              ],
            };

          case 'get_request_rate_status':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(await this.client.getRequestRateStatus(), null, 2),
                },
              ],
            };

          case 'get_account':
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(await this.client.getAccount(), null, 2),
                },
              ],
            };

          case 'get_sites': {
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const siteName = args?.siteName;
            const getAllPages = args?.getAllPages || false;

            if (getAllPages) {
              const sites = await this.client.getAllPages(
                (p, m) => this.client!.getAccountSites(p, m, siteName),
                max
              );
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ totalItems: sites.length, items: sites }, null, 2),
                  },
                ],
              };
            } else {
              const result = await this.client.getAccountSites(page, max, siteName);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                  },
                ],
              };
            }
          }

          case 'get_devices': {
            const siteUid = args?.siteUid;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;
            const withNetworkInterface = args?.withNetworkInterface || false;

            if (siteUid) {
              if (withNetworkInterface) {
                if (getAllPages) {
                  const devices = await this.client.getAllPages(
                    (p, m) => this.client!.getSiteDevicesWithNetworkInterface(siteUid, p, m),
                    max
                  );
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify({ totalItems: devices.length, items: devices }, null, 2),
                      },
                    ],
                  };
                } else {
                  const result = await this.client.getSiteDevicesWithNetworkInterface(siteUid, page, max);
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify(result, null, 2),
                      },
                    ],
                  };
                }
              }
            } else {
              // Account devices
              const filters = {
                filterId: args?.filterId,
                hostname: args?.hostname,
                deviceType: args?.deviceType,
                operatingSystem: args?.operatingSystem,
                siteName: args?.siteName,
              };
              
              if (getAllPages) {
                const devices = await this.client.getAllPages(
                  (p, m) => this.client!.getAccountDevices(p, m, filters),
                  max
                );
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify({ totalItems: devices.length, items: devices }, null, 2),
                    },
                  ],
                };
              } else {
                const result = await this.client.getAccountDevices(page, max, filters);
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(result, null, 2),
                    },
                  ],
                };
              }
            }
          }

          case 'get_device': {
            const deviceUid = args?.deviceUid;
            const deviceId = args?.deviceId;
            const macAddress = args?.macAddress;

            if (!deviceUid && !deviceId && !macAddress) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Either deviceUid, deviceId, or macAddress must be provided'
              );
            }

            let result;
            if (deviceUid) {
              result = await this.client.getDevice(deviceUid);
            } else if (deviceId) {
              result = await this.client.getDeviceById(deviceId);
            } else {
              result = await this.client.getDeviceByMacAddress(macAddress);
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_alerts': {
            const scope = args?.scope;
            const uid = args?.uid;
            const status = args?.status || 'open';
            const muted = args?.muted;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            let result;
            switch (scope) {
              case 'account':
                if (getAllPages) {
                  result = await this.client.getAllPages(
                    (p, m) => this.client!.getAccountAlerts(status, p, m, muted),
                    max
                  );
                  result = { totalItems: result.length, items: result };
                } else {
                  result = await this.client.getAccountAlerts(status, page, max, muted);
                }
                break;
              case 'site':
                if (!uid) throw new McpError(ErrorCode.InvalidParams, 'Site UID required');
                if (getAllPages) {
                  result = await this.client.getAllPages(
                    (p, m) => this.client!.getSiteAlerts(uid, status, p, m, muted),
                    max
                  );
                  result = { totalItems: result.length, items: result };
                } else {
                  result = await this.client.getSiteAlerts(uid, status, page, max, muted);
                }
                break;
              case 'device':
                if (!uid) throw new McpError(ErrorCode.InvalidParams, 'Device UID required');
                if (getAllPages) {
                  result = await this.client.getAllPages(
                    (p, m) => this.client!.getDeviceAlerts(uid, status, p, m, muted),
                    max
                  );
                  result = { totalItems: result.length, items: result };
                } else {
                  result = await this.client.getDeviceAlerts(uid, status, page, max, muted);
                }
                break;
              default:
                throw new McpError(ErrorCode.InvalidParams, 'Invalid scope');
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_alert': {
            const alertUid = args?.alertUid;
            if (!alertUid) {
              throw new McpError(ErrorCode.InvalidParams, 'Alert UID required');
            }

            const result = await this.client.getAlert(alertUid);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_device_audit': {
            const deviceUid = args?.deviceUid;
            const macAddress = args?.macAddress;
            const deviceClass = args?.deviceClass || 'device';

            if (!deviceUid && !macAddress) {
              throw new McpError(ErrorCode.InvalidParams, 'Either deviceUid or macAddress required');
            }

            let result;
            if (deviceClass === 'device') {
              result = macAddress 
                ? await this.client.getDeviceAuditByMacAddress(macAddress)
                : await this.client.getDeviceAudit(deviceUid);
            } else if (deviceClass === 'esxihost') {
              if (macAddress) throw new McpError(ErrorCode.InvalidParams, 'ESXi audit does not support MAC address lookup');
              result = await this.client.getESXiHostAudit(deviceUid);
            } else if (deviceClass === 'printer') {
              if (macAddress) throw new McpError(ErrorCode.InvalidParams, 'Printer audit does not support MAC address lookup');
              result = await this.client.getPrinterAudit(deviceUid);
            } else {
              throw new McpError(ErrorCode.InvalidParams, 'Invalid device class');
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_device_software': {
            const deviceUid = args?.deviceUid;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            if (!deviceUid) {
              throw new McpError(ErrorCode.InvalidParams, 'Device UID required');
            }

            if (getAllPages) {
              const software = await this.client.getAllPages(
                (p, m) => this.client!.getDeviceSoftware(deviceUid, p, m),
                max
              );
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ totalItems: software.length, items: software }, null, 2),
                  },
                ],
              };
            } else {
              const result = await this.client.getDeviceSoftware(deviceUid, page, max);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                  },
                ],
              };
            }
          }

          case 'get_jobs': {
            const jobUid = args?.jobUid;
            const deviceUid = args?.deviceUid;
            const includeComponents = args?.includeComponents || false;
            const includeStdOut = args?.includeStdOut || false;
            const includeStdErr = args?.includeStdErr || false;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);

            if (!jobUid) {
              throw new McpError(ErrorCode.InvalidParams, 'Job UID required');
            }

            let result: any = await this.client.getJob(jobUid);

            if (includeComponents) {
              result.components = await this.client.getJobComponents(jobUid, page, max);
            }

            if (deviceUid) {
              result.results = await this.client.getJobResults(jobUid, deviceUid);
              
              if (includeStdOut) {
                result.stdout = await this.client.getJobStdOut(jobUid, deviceUid);
              }
              
              if (includeStdErr) {
                result.stderr = await this.client.getJobStdErr(jobUid, deviceUid);
              }
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_users': {
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            if (getAllPages) {
              const users = await this.client.getAllPages(
                (p, m) => this.client!.getAccountUsers(p, m),
                max
              );
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ totalItems: users.length, items: users }, null, 2),
                  },
                ],
              };
            } else {
              const result = await this.client.getAccountUsers(page, max);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                  },
                ],
              };
            }
          }

          case 'get_components': {
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            if (getAllPages) {
              const components = await this.client.getAllPages(
                (p, m) => this.client!.getAccountComponents(p, m),
                max
              );
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ totalItems: components.length, items: components }, null, 2),
                  },
                ],
              };
            } else {
              const result = await this.client.getAccountComponents(page, max);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                  },
                ],
              };
            }
          }

          case 'get_activity_logs': {
            const params = {
              from: args?.from,
              until: args?.until,
              entities: args?.entities,
              categories: args?.categories,
              actions: args?.actions,
              siteIds: args?.siteIds,
              userIds: args?.userIds,
              size: args?.size || 20,
              order: args?.order || 'desc',
            };

            // Remove undefined values
            Object.keys(params).forEach(key => 
              params[key] === undefined && delete params[key]
            );

            const result = await this.client.getActivityLogs(params);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_filters': {
            const type = args?.type;
            const siteUid = args?.siteUid;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            let result;
            if (type === 'default') {
              if (getAllPages) {
                result = await this.client.getAllPages(
                  (p, m) => this.client!.getDefaultFilters(p, m),
                  max
                );
                result = { totalItems: result.length, items: result };
              } else {
                result = await this.client.getDefaultFilters(page, max);
              }
            } else if (type === 'custom') {
              if (getAllPages) {
                result = await this.client.getAllPages(
                  (p, m) => this.client!.getCustomFilters(p, m),
                  max
                );
                result = { totalItems: result.length, items: result };
              } else {
                result = await this.client.getCustomFilters(page, max);
              }
            } else if (type === 'site') {
              if (!siteUid) {
                throw new McpError(ErrorCode.InvalidParams, 'Site UID required for site filters');
              }
              if (getAllPages) {
                result = await this.client.getAllPages(
                  (p, m) => this.client!.getSiteFilters(siteUid, p, m),
                  max
                );
                result = { totalItems: result.length, items: result };
              } else {
                result = await this.client.getSiteFilters(siteUid, page, max);
              }
            } else {
              throw new McpError(ErrorCode.InvalidParams, 'Invalid filter type');
            }

            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_site_settings': {
            const siteUid = args?.siteUid;
            if (!siteUid) {
              throw new McpError(ErrorCode.InvalidParams, 'Site UID required');
            }

            const result = await this.client.getSiteSettings(siteUid);
            return {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };
          }

          case 'get_variables': {
            const scope = args?.scope;
            const siteUid = args?.siteUid;
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            if (scope === 'account') {
              if (getAllPages) {
                const variables = await this.client.getAllPages(
                  (p, m) => this.client!.getAccountVariables(p, m),
                  max
                );
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify({ totalItems: variables.length, items: variables }, null, 2),
                    },
                  ],
                };
              } else {
                const result = await this.client.getAccountVariables(page, max);
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(result, null, 2),
                    },
                  ],
                };
              }
            } else if (scope === 'site') {
              if (!siteUid) {
                throw new McpError(ErrorCode.InvalidParams, 'Site UID required for site scope');
              }
              if (getAllPages) {
                const variables = await this.client.getAllPages(
                  (p, m) => this.client!.getSiteVariables(siteUid, p, m),
                  max
                );
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify({ totalItems: variables.length, items: variables }, null, 2),
                    },
                  ],
                };
              } else {
                const result = await this.client.getSiteVariables(siteUid, page, max);
                return {
                  content: [
                    {
                      type: 'text',
                      text: JSON.stringify(result, null, 2),
                    },
                  ],
                };
              }
            } else {
              throw new McpError(ErrorCode.InvalidParams, 'Invalid scope');
            }
          }

          case 'get_dnet_site_mappings': {
            const page = args?.page || 1;
            const max = Math.min(args?.max || 50, 250);
            const getAllPages = args?.getAllPages || false;

            if (getAllPages) {
              const mappings = await this.client.getAllPages(
                (p, m) => this.client!.getDnetSiteMappings(p, m),
                max
              );
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify({ totalItems: mappings.length, items: mappings }, null, 2),
                  },
                ],
              };
            } else {
              const result = await this.client.getDnetSiteMappings(page, max);
              return {
                content: [
                  {
                    type: 'text',
                    text: JSON.stringify(result, null, 2),
                  },
                ],
              };
            }
          }

          default:
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
      } catch (error) {
        if (error instanceof McpError) {
          throw error;
        }
        
        const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
        throw new McpError(ErrorCode.InternalError, `API error: ${errorMessage}`);
      }
    });
  }

  async initialize(config: Config) {
    this.client = new DattoRMMClient(config);
    // Test authentication on initialization
    await this.client.getAccount();
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Datto RMM MCP Server running on stdio');
  }
}

// Main entry point
async function main() {
  const server = new DattoRMMMCPServer();
  
  // Get configuration from environment variables or command line arguments
  const config: Config = {
    apiUrl: process.env.DATTO_API_URL || '',
    apiKey: process.env.DATTO_API_KEY || '',
    apiSecretKey: process.env.DATTO_API_SECRET_KEY || '',
    refreshIntervalMinutes: parseInt(process.env.DATTO_REFRESH_INTERVAL || '90'),
  };

  // Validate configuration
  try {
    ConfigSchema.parse(config);
  } catch (error) {
    console.error('Invalid configuration:', error);
    console.error('\nRequired environment variables:');
    console.error('  DATTO_API_URL: Your Datto RMM API URL (e.g., https://concord-api.centrastage.net)');
    console.error('  DATTO_API_KEY: Your API Key');
    console.error('  DATTO_API_SECRET_KEY: Your API Secret Key');
    console.error('\nOptional environment variables:');
    console.error('  DATTO_REFRESH_INTERVAL: Token refresh interval in minutes (default: 90)');
    process.exit(1);
  }

  try {
    await server.initialize(config);
    await server.run();
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle process termination
process.on('SIGINT', () => {
  console.error('Server shutting down...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.error('Server shutting down...');
  process.exit(0);
});

// Run the server
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
                  };
                }
              } else {
                const filterId = args?.filterId;
                if (getAllPages) {
                  const devices = await this.client.getAllPages(
                    (p, m) => this.client!.getSiteDevices(siteUid, p, m, filterId),
                    max
                  );
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify({ totalItems: devices.length, items: devices }, null, 2),
                      },
                    ],
                  };
                } else {
                  const result = await this.client.getSiteDevices(siteUid, page, max, filterId);
                  return {
                    content: [
                      {
                        type: 'text',
                        text: JSON.stringify(result, null, 2),
                      },
                    ],
                  