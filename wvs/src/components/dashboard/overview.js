"use client"

import { LineChart, Line, XAxis, YAxis, ResponsiveContainer, Tooltip, CartesianGrid, Legend } from "recharts"

const data = [
  { name: "Mon", totalScanned: 3500, threatsDetected: 250, suspicious: 120 },
  { name: "Tue", totalScanned: 4200, threatsDetected: 380, suspicious: 150 },
  { name: "Wed", totalScanned: 3800, threatsDetected: 290, suspicious: 130 },
  { name: "Thu", totalScanned: 4100, threatsDetected: 310, suspicious: 140 },
  { name: "Fri", totalScanned: 4800, threatsDetected: 420, suspicious: 180 },
  { name: "Sat", totalScanned: 3200, threatsDetected: 280, suspicious: 110 },
  { name: "Sun", totalScanned: 3900, threatsDetected: 340, suspicious: 160 },
]

export function Overview() {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <LineChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
        <XAxis 
          dataKey="name" 
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          axisLine={false}
        />
        <YAxis 
          stroke="#6b7280"
          fontSize={12}
          tickLine={false}
          axisLine={false}
          tickFormatter={(value) => `${value}`}
        />
        <Tooltip 
          contentStyle={{ 
            backgroundColor: 'white',
            border: '1px solid #e5e7eb',
            borderRadius: '6px'
          }}
        />
        <Legend />
        <Line 
          type="monotone" 
          dataKey="totalScanned" 
          stroke="#3b82f6" 
          strokeWidth={2}
          name="URLs Scanned"
        />
        <Line 
          type="monotone" 
          dataKey="threatsDetected" 
          stroke="#ef4444" 
          strokeWidth={2}
          name="Threats Detected"
        />
        <Line 
          type="monotone" 
          dataKey="suspicious" 
          stroke="#f97316" 
          strokeWidth={2}
          name="Suspicious URLs"
        />
      </LineChart>
    </ResponsiveContainer>
  )
}