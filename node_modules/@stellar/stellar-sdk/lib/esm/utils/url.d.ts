export type UrlTemplateValue = string | number | boolean | string[];
export declare function expandUriTemplate(template: string, variables: Record<string, UrlTemplateValue | undefined>, baseUrl?: string | URL): string;
