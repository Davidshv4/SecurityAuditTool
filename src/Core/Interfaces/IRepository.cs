using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecurityAuditTool.Core.Interfaces
{
    /// <summary>
    /// Generic repository interface for database operations
    /// </summary>
    /// <typeparam name="T">The entity type</typeparam>
    public interface IRepository<T> where T : class
    {
        /// <summary>
        /// Gets an entity by ID
        /// </summary>
        /// <param name="id">The ID of the entity</param>
        /// <returns>The entity</returns>
        Task<T> GetByIdAsync(Guid id);
        
        /// <summary>
        /// Gets all entities
        /// </summary>
        /// <returns>A list of all entities</returns>
        Task<IEnumerable<T>> GetAllAsync();
        
        /// <summary>
        /// Adds a new entity
        /// </summary>
        /// <param name="entity">The entity to add</param>
        /// <returns>The added entity</returns>
        Task<T> AddAsync(T entity);
        
        /// <summary>
        /// Updates an existing entity
        /// </summary>
        /// <param name="entity">The entity to update</param>
        /// <returns>The updated entity</returns>
        Task<T> UpdateAsync(T entity);
        
        /// <summary>
        /// Deletes an entity
        /// </summary>
        /// <param name="id">The ID of the entity to delete</param>
        /// <returns>True if successful, false otherwise</returns>
        Task<bool> DeleteAsync(Guid id);
    }
} 