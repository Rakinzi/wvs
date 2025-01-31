"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Overview } from "@/components/dashboard/overview"
import { BlacklistedSites } from "@/components/dashboard/blacklisted-sites"
import { Shield, Link2, AlertTriangle, Scan } from "lucide-react"

export default function Dashboard() {
  return (
    <div className="flex-1 space-y-4 p-8 pt-6 bg-gray-100">
      <div className="flex items-center justify-between space-y-2">
        <h2 className="text-3xl font-bold tracking-tight text-gray-900">Dashboard</h2>
      </div>

      {/* Metric Cards */}
      
<div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
  <Card className="bg-white shadow-lg">
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium text-gray-900">Total Scanned</CardTitle>
      <Scan className="h-4 w-4 text-gray-500" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold text-gray-900">23,145</div>
      <p className="text-xs text-blue-600">+2,107 last 24 hours</p>
    </CardContent>
  </Card>
  <Card className="bg-white shadow-lg">
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium text-gray-900">Blocked Sites</CardTitle>
      <Shield className="h-4 w-4 text-gray-500" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold text-gray-900">1,234</div>
      <p className="text-xs text-red-600">+127 new threats</p>
    </CardContent>
  </Card>
  <Card className="bg-white shadow-lg">
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium text-gray-900">Suspicious URLs</CardTitle>
      <AlertTriangle className="h-4 w-4 text-gray-500" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold text-gray-900">432</div>
      <p className="text-xs text-orange-600">+89 under review</p>
    </CardContent>
  </Card>
  <Card className="bg-white shadow-lg">
    <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
      <CardTitle className="text-sm font-medium text-gray-900">Safe Sites</CardTitle>
      <Link2 className="h-4 w-4 text-gray-500" />
    </CardHeader>
    <CardContent>
      <div className="text-2xl font-bold text-gray-900">21,479</div>
      <p className="text-xs text-green-600">92.8% success rate</p>
    </CardContent>
  </Card>
</div>

      {/* Charts and Recent Sales */}
      <div className="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-1 md:col-span-2 lg:col-span-4 bg-white shadow-lg">
          <CardHeader>
            <CardTitle className="text-gray-900">Overview</CardTitle>
          </CardHeader>
          <CardContent className="h-[300px] sm:h-[350px] lg:h-[400px]">
            <Overview />
          </CardContent>
        </Card>
        <Card className="col-span-1 md:col-span-2 lg:col-span-3 bg-white shadow-lg overflow-hidden">
          <CardHeader>
            <CardTitle className="text-gray-900">Blacklisted Sites</CardTitle>
          </CardHeader>
          <CardContent className="p-0 sm:p-6">
            <BlacklistedSites />
          </CardContent>
        </Card>
    
      </div>
    </div>
  )
}