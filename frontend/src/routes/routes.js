import React, { useState, useEffect } from 'react'
import { RouterProvider, createBrowserRouter, Outlet } from 'react-router-dom'
import { Home, Boxes, CircleHelp } from 'lucide-react'
import { HomePage } from '../homePage/home'
import { HelpPage } from '../helpPage/help'
import { LoginPage } from '../auth/login'
import { SignUpPage } from '../auth/signup'
import { ProtectedRoute } from '../auth/protectedRoute'
import { VEXsPage } from '../vexsPage/vexs'
import { ShowVEXPage } from '../vexsPage/showVex/vex'
import Sidebar, { SidebarItem } from '../components/sidebar'
import PageNotFound from '../errorPage/error'

const API_URL = process.env.REACT_APP_API_URL

function Routes() {
  const [is_logged, set_is_logged] = useState(false)

  useEffect(() => {
    const access_token = localStorage.getItem('access_token')
    fetch(`${API_URL}/auth/verify_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ access_token })
    })
      .then((r) => r.json())
      .then((r) => {
        if (r.valid) {
          set_is_logged(true)
        } else {
          localStorage.removeItem('access_token')
          set_is_logged(false)
        }
      })
  }, [])

  const SidebarLayout = () => (
    <>
      <Sidebar is_logged={is_logged}>
        <SidebarItem icon={<Home size={20} />} text='Home' route='/' />
        {is_logged ? <SidebarItem icon={<Boxes size={20} />} text='VEX Generation' route='/vex' /> : null}
        <SidebarItem icon={<CircleHelp size={20} />} text='Help' route='/help' />
      </Sidebar>
      <Outlet />
    </>
  )

  const routes_for_sidebar = [
    {
      path: '/',
      element: <HomePage is_logged={is_logged} />
    },
    {
      path: '/login',
      element: <LoginPage />
    },
    {
      path: '/signup',
      element: <SignUpPage />
    },
    {
      path: '/help',
      element: <HelpPage />
    },
    {
      path: '/',
      element: <ProtectedRoute />,
      children: [
        {
          path: '/vex',
          element: <VEXsPage />
        },
        {
          path: '/vex/:id',
          element: <ShowVEXPage />
        }
      ]
    }
  ]

  const routes_for_public = [
    {
      path: '/',
      element: <HomePage is_logged={is_logged} />
    },
    {
      path: '/login',
      element: <LoginPage />
    },
    {
      path: '/signup',
      element: <SignUpPage />
    },
    {
      path: '/help',
      element: <HelpPage />
    }
  ]

  const routes_for_authenticated_only = [
    {
      path: '/',
      element: <ProtectedRoute />,
      children: [
        {
          path: '/vex',
          element: <VEXsPage />
        },
        {
          path: '/vex/:id',
          element: <ShowVEXPage />
        }
      ]
    }
  ]

  const router = createBrowserRouter([
    {
      element: <SidebarLayout />,
      errorElement: <PageNotFound />,
      children: [...routes_for_sidebar]
    },
    ...routes_for_public,
    ...routes_for_authenticated_only
  ])

  return <RouterProvider router={router} />
}

export default Routes
