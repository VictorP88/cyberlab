import type { Metadata } from "next";
import { Press_Start_2P, VT323 } from "next/font/google";
import "./globals.css";

const pressStart = Press_Start_2P({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-pixel",
  display: "swap",
});

const vt323 = VT323({
  weight: "400",
  subsets: ["latin"],
  variable: "--font-mono-pixel",
  display: "swap",
});

export const metadata: Metadata = {
  title: "CyberLab",
  description: "Cenários de treinamento em cibersegurança gerados por LLM",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={pressStart.variable + " " + vt323.variable}>
      <body>{children}</body>
    </html>
  );
}
