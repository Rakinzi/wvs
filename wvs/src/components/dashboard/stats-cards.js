const StatsCards = () => {
  const stats = [
    { title: "Total Sales", value: "$10,000", change: "+5%" },
    { title: "Total Orders", value: "150", change: "+10%" },
    { title: "Total Customers", value: "120", change: "+8%" },
    { title: "Total Products", value: "80", change: "+2%" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat, index) => (
        <div key={index} className="bg-white p-4 rounded-lg shadow">
          <h3 className="text-lg font-semibold">{stat.title}</h3>
          <p className="text-2xl font-bold">{stat.value}</p>
          <p className={`text-sm ${stat.change.startsWith('+') ? 'text-green-500' : 'text-red-500'}`}>
            {stat.change}
          </p>
        </div>
      ))}
    </div>
  );
};

export default StatsCards;