// src/pages/Dashboard.jsx
import React, { useEffect, useState } from 'react'
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import API from '../services/api'
import { logout, getRole, getToken } from '../services/auth'
import { useNavigate } from 'react-router-dom'
import AddCrimeForm from '../components/AddCrimeForm'
import CrimeList from '../components/CrimeList'
import L from 'leaflet'
import { io } from 'socket.io-client'

delete L.Icon.Default.prototype._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: new URL('leaflet/dist/images/marker-icon-2x.png', import.meta.url).href,
  iconUrl: new URL('leaflet/dist/images/marker-icon.png', import.meta.url).href,
  shadowUrl: new URL('leaflet/dist/images/marker-shadow.png', import.meta.url).href,
})

const Dashboard = () => {
  const [crimes, setCrimes] = useState([])
  const [loading, setLoading] = useState(false)
  const [myLocation, setMyLocation] = useState(null)
  const navigate = useNavigate()
  const role = getRole() || 'user'

  // ---- Socket.IO setup ----
  const [socket, setSocket] = useState(null)
  useEffect(() => {
    const token = getToken()
    if (!token) return
    const newSocket = io('http://127.0.0.1:5000', {
      auth: { token },
    })
    newSocket.on('connect', () => console.log('Socket connected'))
    newSocket.on('disconnect', () => console.log('Socket disconnected'))
    newSocket.on('crime_zone_alert', (data) => {
      alert(`⚠️ Crime Alert: ${data.message}`)
    })
    setSocket(newSocket)
    return () => newSocket.disconnect()
  }, [])

  // ---- Fetch crimes on load ----
  useEffect(() => {
    fetchCrimes()
  }, [])

  // ---- Fetch user's location and send to backend ----
  useEffect(() => {
    const fetchUserLocation = async () => {
      if (!navigator.geolocation) return alert('Geolocation not supported')
      navigator.geolocation.getCurrentPosition(
        async (pos) => {
          const lat = pos.coords.latitude
          const lng = pos.coords.longitude
          setMyLocation({ lat, lng })

          try {
            const res = await API.post('/api/location/update', { latitude: lat, longitude: lng })
            if (res.data?.alert) {
              res.data.alerts.forEach(a => {
                alert(`⚠️ ${a.message}`)
              })
            }
          } catch (err) {
            console.error('Location update failed', err)
          }
        },
        (err) => {
          alert('Unable to fetch location: ' + err.message)
        },
        { enableHighAccuracy: true }
      )
    }
    fetchUserLocation()
  }, [])

  const fetchCrimes = async () => {
    try {
      setLoading(true)
      const res = await API.get('/api/crimes')
      setCrimes(res.data)
    } catch (err) {
      console.error(err)
      if (err?.response?.status === 401) {
        logout()
        navigate('/login')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  const handleDelete = async (location) => {
    if (!window.confirm(`Delete crime at ${location}?`)) return
    try {
      const res = await API.delete(`/api/crimes/${encodeURIComponent(location)}`)
      alert(res.data.message)
      fetchCrimes()
    } catch (err) {
      alert(err?.response?.data?.message || 'Delete failed')
    }
  }

  const handleAlertPatrol = async (crime) => {
    try {
      const body = {
        location: crime.location,
        message: `Patrol requested for ${crime.location} - ${crime.type}`,
        lat: crime.lat,
        lng: crime.lng,
      }
      const res = await API.post('/api/alert', body)
      alert(res.data.message)
    } catch (err) {
      console.error(err)
      alert('Failed to send alert')
    }
  }

  return (
    <div>
      <div className="flex justify-between p-4 bg-gray-800 text-white">
        <h2 className="text-xl">CrimeSpot Dashboard ({role})</h2>
        <div className="flex gap-2 items-center">
          <button onClick={handleLogout} className="bg-red-500 px-3 py-1 rounded">
            Logout
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4">
        <div className="md:col-span-2 h-[70vh] bg-white rounded shadow overflow-hidden">
          <MapContainer
            center={myLocation ? [myLocation.lat, myLocation.lng] : [13.0827, 80.2707]}
            zoom={13}
            style={{ height: '100%', width: '100%' }}
          >
            <TileLayer url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png" />
            {crimes.map(
              (crime, idx) =>
                crime.lat &&
                crime.lng && (
                  <Marker key={idx} position={[crime.lat, crime.lng]}>
                    <Popup>
                      <div className="font-bold">{crime.location}</div>
                      <div>{crime.type}</div>
                      <div className="text-xs">{crime.date}</div>
                      <div className="mt-2 flex gap-2">
                        {role === 'admin' && (
                          <button
                            onClick={() => handleDelete(crime.location)}
                            className="bg-red-500 text-white px-2 py-1 rounded"
                          >
                            Delete
                          </button>
                        )}
                        <button
                          onClick={() => handleAlertPatrol(crime)}
                          className="bg-blue-600 text-white px-2 py-1 rounded"
                        >
                          Alert Patrol
                        </button>
                      </div>
                    </Popup>
                  </Marker>
                )
            )}
            {myLocation && (
              <Marker position={[myLocation.lat, myLocation.lng]}>
                <Popup>You are here</Popup>
              </Marker>
            )}
          </MapContainer>
        </div>

        <div className="space-y-4">
          {role === 'admin' && (
            <div className="bg-white p-4 rounded shadow">
              <h3 className="font-semibold mb-2">Add crime</h3>
              <AddCrimeForm onAdded={fetchCrimes} useLocation={myLocation} />
            </div>
          )}
          <div className="bg-white p-4 rounded shadow">
            <h3 className="font-semibold mb-2">Crime list</h3>
            <CrimeList crimes={crimes} onDelete={handleDelete} onAlert={handleAlertPatrol} role={role} />
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
