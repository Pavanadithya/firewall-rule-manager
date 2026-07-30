import { useEffect, useState } from 'react';
import axios from 'axios';

const API_BASE = 'http://localhost:8000/api/v1';

export default function Dashboard() {
  const [firewalls, setFirewalls] = useState([]);
  const [rules, setRules] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [firewallRes, rulesRes, summaryRes] = await Promise.all([
        axios.get(`${API_BASE}/firewalls`),
        axios.get(`${API_BASE}/rules`),
        axios.get(`${API_BASE}/analysis/summary`)
      ]);

      setFirewalls(firewallRes.data.data || []);
      setRules(rulesRes.data.data || []);
      setSummary(summaryRes.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching data:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-xl">Loading...</div>;
  }

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      <div className="max-w-7xl mx-auto">
        <h1 className="text-4xl font-bold mb-8">Firewall Rule Manager</h1>

        {summary && (
          <div className="grid grid-cols-4 gap-4 mb-8">
            <Card title="Total Rules" value={summary.total_rules} />
            <Card title="Unused" value={summary.unused_rules} color="orange" />
            <Card title="Redundant" value={summary.redundant_rules} color="red" />
            <Card title="Conflicts" value={summary.conflicting_rules} color="yellow" />
          </div>
        )}

        <div className="bg-white rounded-lg shadow p-6 mb-8">
          <h2 className="text-2xl font-bold mb-4">Firewalls</h2>
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left p-2">Name</th>
                <th className="text-left p-2">Vendor</th>
                <th className="text-left p-2">IP</th>
              </tr>
            </thead>
            <tbody>
              {firewalls.map(fw => (
                <tr key={fw.id} className="border-b hover:bg-gray-50">
                  <td className="p-2">{fw.name}</td>
                  <td className="p-2">{fw.vendor}</td>
                  <td className="p-2 font-mono text-sm">{fw.ip_address}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function Card({ title, value, color = 'blue' }) {
  const colors = {
    blue: 'bg-blue-50',
    orange: 'bg-orange-50',
    red: 'bg-red-50',
    yellow: 'bg-yellow-50'
  };
  return (
    <div className={`${colors[color]} p-6 rounded-lg`}>
      <p className="text-gray-600 text-sm">{title}</p>
      <p className="text-3xl font-bold">{value}</p>
    </div>
  );
}
