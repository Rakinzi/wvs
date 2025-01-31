"use client"

import Link from "next/link"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

export default function RegisterPage() {
    return (
        <div className="h-screen w-screen flex items-center justify-center bg-gray-900">
            <Card className="w-[350px] bg-gray-800 border-gray-700 text-white">
                <CardHeader className="space-y-1">
                    <CardTitle className="text-2xl">Create an account</CardTitle>
                    <CardDescription className="text-gray-400">
                        Enter your information to create an account
                    </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                    <div className="space-y-2">
                        <Input
                            type="text"
                            placeholder="Name"
                            className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-400"
                        />
                    </div>
                    <div className="space-y-2">
                        <Input
                            type="email"
                            placeholder="Email"
                            className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-400"
                        />
                    </div>
                    <div className="space-y-2">
                        <Input
                            type="password"
                            placeholder="Password"
                            className="bg-gray-700 border-gray-600 text-white placeholder:text-gray-400"
                        />
                    </div>
                    <Button
                        variant="secondary"
                        className="w-full"
                    >
                        Register
                    </Button>
                    <div className="text-center text-sm text-gray-400">
                        Already have an account?{' '}
                        <Link href="/auth/login" className="text-blue-400 hover:underline">
                            Login
                        </Link>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}