import { Badge } from "@/components/ui/badge"

const blacklistedSites = [
  {
    url: "malicious-site.com",
    dateAdded: "2024-03-15",
    riskLevel: "High",
    category: "Phishing"
  },
  {
    url: "fake-bank-login.net",
    dateAdded: "2024-03-14",
    riskLevel: "Critical",
    category: "Banking Fraud"
  },
  {
    url: "spam-emails-sender.org",
    dateAdded: "2024-03-13",
    riskLevel: "Medium",
    category: "Spam"
  },
  {
    url: "data-harvester.xyz",
    dateAdded: "2024-03-12",
    riskLevel: "High",
    category: "Data Theft"
  }
]

const getRiskColor = (risk) => {
  switch (risk) {
    case "Critical": return "text-red-600 bg-red-100"
    case "High": return "text-orange-600 bg-orange-100"
    case "Medium": return "text-yellow-600 bg-yellow-100"
    default: return "text-blue-600 bg-blue-100"
  }
}

export function BlacklistedSites() {
  return (
    <div className="space-y-4">
      {blacklistedSites.map((site) => (
        <div key={site.url} className="flex flex-col sm:flex-row items-start sm:items-center p-4 border-b">
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-gray-900 truncate">{site.url}</p>
            <p className="text-xs text-gray-500">Added: {site.dateAdded}</p>
          </div>
          <div className="mt-2 sm:mt-0 flex items-center space-x-2">
            <Badge className={getRiskColor(site.riskLevel)}>
              {site.riskLevel}
            </Badge>
            <span className="text-xs text-gray-500">{site.category}</span>
          </div>
        </div>
      ))}
    </div>
  )
}