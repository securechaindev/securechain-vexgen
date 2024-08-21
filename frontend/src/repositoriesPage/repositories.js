import React, { useState, useEffect } from 'react'
import { ArrowBigDownDash } from 'lucide-react'
import Button from '@mui/material/Button'
import MenuItem from '@mui/material/MenuItem'
import Select from '@mui/material/Select'
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';

const RepositoriesPage = () => {
  const [owner, set_owner] = useState('')
  const [name, set_name] = useState('')
  const [sbom_path, set_sbom_path] = useState('')
  const [statements_group, set_statements_group] = useState('no_grouping')
  const [owner_error, set_owner_error] = useState('')
  const [name_error, set_name_error] = useState('')
  const [sbom_path_error, set_sbom_path_error] = useState('')
  const [vexs, set_vexs] = useState([])

  useEffect(() => {
    const access_token = localStorage.getItem('access_token')
    const user_id = localStorage.getItem('user_id')
    const fetch_vexs= () => {
      fetch('http://localhost:8000/vexs/' + user_id, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${access_token}`
        }
      })
        .then((r) => r.json())
        .then((r) => {
          set_vexs(r)
        })
    }
    fetch_vexs()
    const intervalId = setInterval(fetch_vexs, 10000)
    return () => clearInterval(intervalId)
  }, [])

  const on_button_generate_vex = () => {
    set_owner_error('')
    set_name_error('')
    set_sbom_path_error('')

    if ('' === owner) {
      set_owner_error('Please enter a owner')
      return
    }

    if ('' === name) {
      set_name_error('Please enter a name')
      return
    }

    if ('' === sbom_path) {
      set_sbom_path_error('Please enter a sbom path')
      return
    }

    const user_id = localStorage.getItem('user_id')

    fetch('http://localhost:8000/generate_vex', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ owner, name, sbom_path, statements_group, user_id })
    })
      .then(async response => {
        const disposition = response.headers.get('Content-Disposition')
        var filename = disposition.split(/;(.+)/)[1].split(/=(.+)/)[1]
        if (filename.toLowerCase().startsWith("utf-8''"))
          filename = decodeURIComponent(filename.replace("utf-8''", ''))
        else
          filename = filename.replace(/['"]/g, '')
        var url = window.URL.createObjectURL(await response.blob())
        var a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        a.remove()
      })
  }

  const handle_statements_group_change = (event) => {
    set_statements_group(event.target.value)
  }

  return (
    <div className='flex flex-col h-screen justify-center items-center m-auto'>
      <p className='mb-6 text-lg font-normal text-gray-500 lg:text-xl sm:px-16 xl:px-48 dark:text-gray-400 text-center'>
        You must enter here the owner, name and the SBOM path in a public repository.
      </p>
      <div className='flex gap-4'>
        <input
          value={owner}
          type='text'
          placeholder='Enter the owner here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_owner(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />
        <input
          value={name}
          type='text'
          placeholder='Enter the name here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_name(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />
        <input
          value={sbom_path}
          type='text'
          placeholder='Enter the sbom path here'
          onKeyDown={(e) => {
            if (e.key === 'Enter') on_button_generate_vex()
          }}
          onChange={(ev) => set_sbom_path(ev.target.value)}
          className='w-64 shadow appearance-none border rounded w-full py-2 px-2 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline'
        />
      </div>
      <Select value={statements_group} onChange={handle_statements_group_change}>
        <MenuItem value={'no_grouping'}>No Grouping</MenuItem>
        <MenuItem value={'affected_component_manager'}>Affected Component Manager</MenuItem>
        <MenuItem value={'attack_vector_av'}>Attack Vector AV</MenuItem>
        <MenuItem value={'attack_vector_ac'}>Attack Vector AC</MenuItem>
        <MenuItem value={'attack_vector_au'}>Attack Vector AU</MenuItem>
        <MenuItem value={'attack_vector_c'}>Attack Vector C</MenuItem>
        <MenuItem value={'attack_vector_i'}>Attack Vector I</MenuItem>
        <MenuItem value={'attack_vector_a'}>Attack Vector A</MenuItem>
        <MenuItem value={'reachable_code'}>Reachable Code</MenuItem>
      </Select>
      <br />
      <label className={`text-red-600 ${owner_error !== '' ? '' : 'hidden'}`}>{owner_error}</label>
      <label className={`text-red-600 ${name_error !== '' ? '' : 'hidden'}`}>{name_error}</label>
      <label className={`text-red-600 ${sbom_path_error !== '' ? '' : 'hidden'}`}>{sbom_path_error}</label>
      <Button variant="contained" onClick={on_button_generate_vex}>Generate VEX</Button>
      <TableContainer component={Paper}>
        <Table sx={{ minWidth: 650 }} aria-label="simple table">
          <TableHead>
            <TableRow>
              <TableCell align="center">Owner</TableCell>
              <TableCell align="center">Name</TableCell>
              <TableCell align="center">SBOM Path</TableCell>
              <TableCell align="center">Download VEX</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {vexs.map((row) => (
              <TableRow
                key={row._id}
                sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
              >
                <TableCell align="center">{row.owner}</TableCell>
                <TableCell align="center">{row.name}</TableCell>
                <TableCell align="center">{row.sbom_path}</TableCell>
                <TableCell align="center"><Button size="small" variant="contained" onClick={on_button_generate_vex}><ArrowBigDownDash /></Button></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  )
}

export { RepositoriesPage }
