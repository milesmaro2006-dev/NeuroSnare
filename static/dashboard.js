// الإحصائيات
fetch('/api/stats').then(r=>r.json()).then(d=>{
    document.getElementById('total').innerText = d.total_attacks;
    document.getElementById('redirected').innerText = d.redirected;
    document.getElementById('unique').innerText = d.unique_ips;
});

// ملفات المهاجمين
fetch('/api/profiles').then(r=>r.json()).then(data=>{
    const t = document.getElementById('profileTable');
    data.forEach(row => {
        const tr = document.createElement('tr');
        const risk = row[4] || 0;
        let cls = 'risk-low';
        if (risk > 0.7) cls = 'risk-high';
        else if (risk > 0.4) cls = 'risk-medium';
        tr.innerHTML = `<td>${row[0]}</td><td>${row[3]}</td><td class="${cls}">${(risk*100).toFixed(0)}%</td><td>${row[1] ? '✅' : '❌'}</td>`;
        t.appendChild(tr);
    });
});

// ربط الـ IPs
fetch('/api/correlate').then(r=>r.json()).then(data=>{
    const div = document.getElementById('correlationData');
    if (data.length === 0) { div.innerHTML = '<p>No correlations found.</p>'; return; }
    let html = '<ul>';
    data.forEach(item => {
        html += `<li>🎯 Canvas FP: ${item.canvas_fingerprint.substring(0, 30)}...<br>`;
        html += `IPs: ${item.ips.map(i => i.ip).join(', ')} (Total Attacks: ${item.total_attacks})</li>`;
    });
    html += '</ul>';
    div.innerHTML = html;
});

// جدول الهجمات
fetch('/api/attacks').then(r=>r.json()).then(data=>{
    const t = document.getElementById('attackTable');
    data.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${row[1]}</td><td>${row[2]}</td><td>${row[4]}</td><td>${row[5]}</td><td>${(row[6]*100).toFixed(0)}%</td>`;
        t.appendChild(tr);
    });
});

// رسم بياني
new Chart(document.getElementById('attackChart'), {
    type: 'doughnut',
    data: {
        labels: ['Redirected', 'Blocked'],
        datasets: [{ data: [10, 2], backgroundColor: ['#4fc3f7', '#ef5350'] }]
    }
});
